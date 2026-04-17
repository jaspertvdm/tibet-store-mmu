use std::time::Instant;
use tibet_store_mmu::*;
use tibet_trust_kernel::bifurcation::ClearanceLevel;

/// SCALETEST — How far does the Spaceshuttle scale?
///
/// Tests encrypted + compressed page faults at increasing scale:
///   64 → 256 → 1024 → 4096 → 16384 pages
///   256KB → 1MB → 4MB → 16MB → 64MB virtual arena
///
/// Measures: seal time, fault+decrypt time, compression, p50/p95/p99
/// Answers: does latency stay O(1) per page when arena grows?

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  SCALETEST — Spaceshuttle at Scale                       ║");
    println!("  ║                                                          ║");
    println!("  ║  Encrypted + Compressed page faults: 64 → 16384 pages    ║");
    println!("  ║  Vraag: blijft latency O(1) per page bij schaal?         ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    if !userfaultfd_available() {
        println!("  ✗ userfaultfd niet beschikbaar");
        println!("  Tip: sudo sysctl -w vm.unprivileged_userfaultfd=1");
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    println!("  Page size: {} bytes", page_size);
    println!();

    // Scale levels: pages → virtual arena size
    let scales: &[(usize, &str)] = &[
        (64,    "256 KB"),
        (256,   "1 MB"),
        (1024,  "4 MB"),
        (4096,  "16 MB"),
        (16384, "64 MB"),
    ];

    // ── Header ──
    println!("  {:<8} {:<10} {:<12} {:<12} {:<10} {:<10} {:<10} {:<10} {:<8}",
        "Pages", "Arena", "Seal", "Decrypt", "p50", "p95", "p99", "Storage", "Ratio");
    println!("  {}", "─".repeat(90));

    for &(num_pages, label) in scales {
        let arena_size = page_size * num_pages;

        // ── Generate test data (mixed: text + binary-ish patterns) ──
        let pages: Vec<Vec<u8>> = (0..num_pages)
            .map(|i| {
                let mut page = vec![0u8; page_size];
                // First 256 bytes: structured text (highly compressible)
                let text = format!(
                    "PAGE[{:06}] Encrypted memory illusion — data at rest is \
                     AES-256-GCM sealed, decrypted per-fault via JIS clearance. \
                     Source: scaletest. Timestamp: 2026-04-15. Sequence: {}. \
                     Padding follows to simulate real workload data structures.",
                    i, i * 7 + 42
                );
                let bytes = text.as_bytes();
                page[..bytes.len()].copy_from_slice(bytes);
                // Bytes 256-512: repeating pattern (moderately compressible)
                for j in 256..512.min(page_size) {
                    page[j] = ((i + j) % 256) as u8;
                }
                // Rest: zeros (highly compressible)
                page
            })
            .collect();

        // ── Seal (compress + encrypt) ──
        let t_seal = Instant::now();
        let sealed = seal_pages_compressed(
            &pages,
            ClearanceLevel::Secret,
            "scaletest",
            3,
        );
        let seal_us = t_seal.elapsed().as_micros();
        let seal_per = seal_us / num_pages as u128;

        // ── Create arena ──
        let claim = mmu_claim("scaletest.aint", ClearanceLevel::TopSecret);

        let arena = match MmuArena::new(MmuConfig {
            arena_size,
            fill_mode: FillMode::CompressedEncryptedRestore {
                sealed_pages: sealed.blocks,
                original_sizes: sealed.original_sizes,
                claim,
                clearance: ClearanceLevel::Secret,
            },
            use_hugepages: false,
        }) {
            Some(a) => a,
            None => {
                println!("  {:<8} {:<10} FAILED — arena creation", num_pages, label);
                continue;
            }
        };

        // ── Touch all pages ──
        let t_read = Instant::now();
        let mut verified = 0usize;

        for i in 0..num_pages {
            let offset = i * page_size;
            let read_data = unsafe { arena.read_slice(offset, 40) };
            let text = String::from_utf8_lossy(&read_data);
            if text.starts_with(&format!("PAGE[{:06}]", i)) {
                verified += 1;
            }
        }

        let read_us = t_read.elapsed().as_micros();
        let read_per = read_us / num_pages as u128;

        // ── Collect latencies ──
        let result = arena.shutdown();
        let mut sorted = result.fault_latencies_ns.clone();
        sorted.sort();

        let p50 = if !sorted.is_empty() { format_ns(percentile(&sorted, 50.0)) } else { "-".into() };
        let p95 = if !sorted.is_empty() { format_ns(percentile(&sorted, 95.0)) } else { "-".into() };
        let p99 = if !sorted.is_empty() { format_ns(percentile(&sorted, 99.0)) } else { "-".into() };

        let storage_kb = sealed.total_encrypted / 1024;

        // ── Verification ──
        let status = if verified == num_pages { "✓" } else { "✗" };

        println!("  {:<8} {:<10} {:<12} {:<12} {:<10} {:<10} {:<10} {:<10} {:.1}x {}",
            num_pages,
            label,
            format!("{} µs/pg", seal_per),
            format!("{} µs/pg", read_per),
            p50,
            p95,
            p99,
            format!("{} KB", storage_kb),
            sealed.compression_ratio,
            status,
        );
    }

    println!("  {}", "─".repeat(90));
    println!();

    // ── Encrypt-only comparison at largest scale that ran ──
    println!("  ── Vergelijking: Encrypt-only vs Compressed+Encrypted (1024 pages) ──");
    println!();

    let num_pages = 1024;
    let arena_size = page_size * num_pages;

    let pages: Vec<Vec<u8>> = (0..num_pages)
        .map(|i| {
            let mut page = vec![0u8; page_size];
            let text = format!("PAGE[{:06}] Comparison test data for encrypt-only baseline.", i);
            let bytes = text.as_bytes();
            page[..bytes.len()].copy_from_slice(bytes);
            for j in 256..512.min(page_size) {
                page[j] = ((i + j) % 256) as u8;
            }
            page
        })
        .collect();

    // Encrypt-only
    let t0 = Instant::now();
    let sealed_enc = seal_pages(&pages, ClearanceLevel::Secret, "scaletest-enc");
    let enc_seal_us = t0.elapsed().as_micros();

    let claim_enc = mmu_claim("scaletest-enc.aint", ClearanceLevel::TopSecret);
    let arena_enc = MmuArena::new(MmuConfig {
        arena_size,
        fill_mode: FillMode::EncryptedRestore {
            sealed_pages: sealed_enc,
            claim: claim_enc,
            clearance: ClearanceLevel::Secret,
        },
        use_hugepages: false,
    }).expect("encrypt-only arena");

    let t0 = Instant::now();
    for i in 0..num_pages {
        unsafe { arena_enc.read_slice(i * page_size, 40); }
    }
    let enc_read_us = t0.elapsed().as_micros();
    let enc_result = arena_enc.shutdown();
    let mut enc_sorted = enc_result.fault_latencies_ns.clone();
    enc_sorted.sort();

    // Compressed + Encrypted
    let t0 = Instant::now();
    let sealed_comp = seal_pages_compressed(&pages, ClearanceLevel::Secret, "scaletest-comp", 3);
    let comp_seal_us = t0.elapsed().as_micros();

    let claim_comp = mmu_claim("scaletest-comp.aint", ClearanceLevel::TopSecret);
    let arena_comp = MmuArena::new(MmuConfig {
        arena_size,
        fill_mode: FillMode::CompressedEncryptedRestore {
            sealed_pages: sealed_comp.blocks,
            original_sizes: sealed_comp.original_sizes,
            claim: claim_comp,
            clearance: ClearanceLevel::Secret,
        },
        use_hugepages: false,
    }).expect("compressed arena");

    let t0 = Instant::now();
    for i in 0..num_pages {
        unsafe { arena_comp.read_slice(i * page_size, 40); }
    }
    let comp_read_us = t0.elapsed().as_micros();
    let comp_result = arena_comp.shutdown();
    let mut comp_sorted = comp_result.fault_latencies_ns.clone();
    comp_sorted.sort();

    println!("  {:<26} {:<20} {:<20}", "", "Encrypt-only", "Compress+Encrypt");
    println!("  {}", "─".repeat(66));
    println!("  {:<26} {:>6} µs/pg       {:>6} µs/pg",
        "Seal:", enc_seal_us / num_pages as u128, comp_seal_us / num_pages as u128);
    println!("  {:<26} {:>6} µs/pg       {:>6} µs/pg",
        "Fault+Decrypt:", enc_read_us / num_pages as u128, comp_read_us / num_pages as u128);
    println!("  {:<26} {:>6} KB           {:>6} KB",
        "Storage (1024 pages):", num_pages * page_size / 1024, sealed_comp.total_encrypted / 1024);

    if !enc_sorted.is_empty() && !comp_sorted.is_empty() {
        println!("  {:<26} {:>10}          {:>10}",
            "p50:", format_ns(percentile(&enc_sorted, 50.0)), format_ns(percentile(&comp_sorted, 50.0)));
        println!("  {:<26} {:>10}          {:>10}",
            "p95:", format_ns(percentile(&enc_sorted, 95.0)), format_ns(percentile(&comp_sorted, 95.0)));
        println!("  {:<26} {:>10}          {:>10}",
            "p99:", format_ns(percentile(&enc_sorted, 99.0)), format_ns(percentile(&comp_sorted, 99.0)));
    }

    let speedup = if comp_read_us > 0 {
        enc_read_us as f64 / comp_read_us as f64
    } else { 0.0 };

    println!("  {:<26} {:.1}x", "Compression ratio:", sealed_comp.compression_ratio);
    println!("  {:<26} {:.1}x sneller", "Decrypt speedup:", speedup);
    println!("  {}", "─".repeat(66));
    println!();

    println!("  ═══════════════════════════════════════════════════════════");
    println!("  SCALETEST COMPLEET");
    println!();
    println!("  Conclusie: als latency O(1) per page is bij schaal,");
    println!("  dan is encrypted+compressed RAM lineair schaalbaar.");
    println!("  Minder bytes = sneller decrypten. De wiskunde klopt.");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
}
