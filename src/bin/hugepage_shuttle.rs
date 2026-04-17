use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;
use tibet_store_mmu::*;
use tibet_trust_kernel::bifurcation::ClearanceLevel;

/// HUGEPAGE SHUTTLE — GGUF Weights met 2MB HugePages
///
/// Vergelijking: 4KB pages vs 2MB HugePages
///
/// 18.5GB model:
///   4KB pages:  4,846,517 pages → TLB thrashing (1536 TLB entries)
///   2MB pages:      9,375 pages → past in TLB
///
/// Hypothese: HugePages elimineren TLB overhead, minder faults,
/// betere zstd compressie (meer context per chunk).

const HUGEPAGE_SIZE: usize = 2 * 1024 * 1024; // 2MB

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  HUGEPAGE SHUTTLE — 4KB vs 2MB Page Comparison           ║");
    println!("  ║                                                          ║");
    println!("  ║  Hypothesis: 2MB pages → less TLB thrashing,             ║");
    println!("  ║  fewer faults, better zstd ratio, faster decrypt         ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    if !userfaultfd_available() {
        println!("  ✗ userfaultfd niet beschikbaar");
        return;
    }

    // Find GGUF
    let blob_dir = "/usr/share/ollama/.ollama/models/blobs";
    let gguf_path = find_largest_blob(blob_dir, 1_000_000_000);
    let gguf_path = match gguf_path {
        Some(p) => p,
        None => { println!("  ✗ Geen groot blob gevonden"); return; }
    };

    let file_size = std::fs::metadata(&gguf_path).unwrap().len() as usize;
    println!("  GGUF: {:.2} GB", file_size as f64 / (1024.0 * 1024.0 * 1024.0));

    let normal_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    println!("  Normal page: {} bytes", normal_page);
    println!("  HugePage:    {} bytes ({} KB)", HUGEPAGE_SIZE, HUGEPAGE_SIZE / 1024);
    println!();

    // Test size: 128MB (fits in our 64 pre-allocated hugepages)
    let test_size = 128 * 1024 * 1024;
    let normal_pages = test_size / normal_page;
    let huge_pages = test_size / HUGEPAGE_SIZE;

    println!("  Test size:   {} MB", test_size / (1024 * 1024));
    println!("  Normal:      {} pages (4KB)", normal_pages);
    println!("  HugePages:   {} pages (2MB)", huge_pages);
    println!("  TLB ratio:   {}x minder entries", normal_pages / huge_pages);
    println!();

    // ═══════════════════════════════════════════════════════
    // TEST A: Normal 4KB pages
    // ═══════════════════════════════════════════════════════
    println!("  ── A: Normal 4KB Pages ──");

    let pages_4k = read_file_pages(&gguf_path, test_size, normal_page);
    assert_eq!(pages_4k.len(), normal_pages);

    let t0 = Instant::now();
    let sealed_4k = seal_pages_compressed(
        &pages_4k, ClearanceLevel::Secret, "hugepage-4k", 3,
    );
    let seal_4k_ms = t0.elapsed().as_millis();
    drop(pages_4k);

    let claim_4k = mmu_claim("hugepage-4k.aint", ClearanceLevel::TopSecret);
    let arena_4k = MmuArena::new(MmuConfig {
        arena_size: test_size,
        fill_mode: FillMode::CompressedEncryptedRestore {
            sealed_pages: sealed_4k.blocks,
            original_sizes: sealed_4k.original_sizes,
            claim: claim_4k,
            clearance: ClearanceLevel::Secret,
        },
        use_hugepages: false,
    }).expect("4KB arena");

    let t0 = Instant::now();
    let mut checksum_4k: u64 = 0;
    for i in 0..normal_pages {
        let data = unsafe { arena_4k.read_slice(i * normal_page, 8) };
        for &b in &data { checksum_4k = checksum_4k.wrapping_add(b as u64); }
    }
    let decrypt_4k_ms = t0.elapsed().as_millis();

    let result_4k = arena_4k.shutdown();
    let mut lat_4k = result_4k.fault_latencies_ns.clone();
    lat_4k.sort();

    let throughput_4k = test_size as f64 / (1024.0 * 1024.0) / (decrypt_4k_ms as f64 / 1000.0);

    println!("  Seal:       {} ms ({} µs/pg)", seal_4k_ms,
        seal_4k_ms * 1000 / normal_pages as u128);
    println!("  Decrypt:    {} ms ({} µs/pg)", decrypt_4k_ms,
        decrypt_4k_ms * 1000 / normal_pages as u128);
    println!("  Faults:     {}", result_4k.stats.pages_faulted);
    println!("  Throughput: {:.0} MB/s", throughput_4k);
    println!("  Ratio:      {:.1}x", sealed_4k.compression_ratio);
    if !lat_4k.is_empty() {
        println!("  p50: {}  p95: {}  p99: {}",
            format_ns(percentile(&lat_4k, 50.0)),
            format_ns(percentile(&lat_4k, 95.0)),
            format_ns(percentile(&lat_4k, 99.0)));
    }
    println!("  Checksum:   {:016x}", checksum_4k);
    println!();

    // ═══════════════════════════════════════════════════════
    // TEST B: 2MB HugePages
    // ═══════════════════════════════════════════════════════
    println!("  ── B: 2MB HugePages ──");

    let pages_2m = read_file_pages(&gguf_path, test_size, HUGEPAGE_SIZE);
    assert_eq!(pages_2m.len(), huge_pages);

    let t0 = Instant::now();
    let sealed_2m = seal_pages_compressed(
        &pages_2m, ClearanceLevel::Secret, "hugepage-2m", 3,
    );
    let seal_2m_ms = t0.elapsed().as_millis();
    drop(pages_2m);

    let claim_2m = mmu_claim("hugepage-2m.aint", ClearanceLevel::TopSecret);
    let arena_2m = MmuArena::new(MmuConfig {
        arena_size: test_size,
        fill_mode: FillMode::CompressedEncryptedRestore {
            sealed_pages: sealed_2m.blocks,
            original_sizes: sealed_2m.original_sizes,
            claim: claim_2m,
            clearance: ClearanceLevel::Secret,
        },
        use_hugepages: true,
    }).expect("2MB arena — did you run: sudo sysctl vm.nr_hugepages=64?");

    let t0 = Instant::now();
    let mut checksum_2m: u64 = 0;
    // Touch each hugepage — only 64 faults vs 32768 faults
    for i in 0..huge_pages {
        let data = unsafe { arena_2m.read_slice(i * HUGEPAGE_SIZE, 8) };
        for &b in &data { checksum_2m = checksum_2m.wrapping_add(b as u64); }
    }
    let decrypt_2m_ms = t0.elapsed().as_millis();

    let result_2m = arena_2m.shutdown();
    let mut lat_2m = result_2m.fault_latencies_ns.clone();
    lat_2m.sort();

    let throughput_2m = test_size as f64 / (1024.0 * 1024.0) / (decrypt_2m_ms as f64 / 1000.0);

    println!("  Seal:       {} ms ({} µs/pg)", seal_2m_ms,
        if huge_pages > 0 { seal_2m_ms * 1000 / huge_pages as u128 } else { 0 });
    println!("  Decrypt:    {} ms ({} µs/pg)", decrypt_2m_ms,
        if huge_pages > 0 { decrypt_2m_ms * 1000 / huge_pages as u128 } else { 0 });
    println!("  Faults:     {}", result_2m.stats.pages_faulted);
    println!("  Throughput: {:.0} MB/s", throughput_2m);
    println!("  Ratio:      {:.1}x", sealed_2m.compression_ratio);
    if !lat_2m.is_empty() {
        println!("  p50: {}  p95: {}  p99: {}",
            format_ns(percentile(&lat_2m, 50.0)),
            format_ns(percentile(&lat_2m, 95.0)),
            format_ns(percentile(&lat_2m, 99.0)));
    }
    println!("  Checksum:   {:016x}", checksum_2m);
    println!();

    // ═══════════════════════════════════════════════════════
    // COMPARISON
    // ═══════════════════════════════════════════════════════
    println!("  ══════════════════════════════════════════════════════════════");
    println!("  VERGELIJKING — {} MB GGUF Weights", test_size / (1024 * 1024));
    println!("  ──────────────────────────────────────────────────────────────");
    println!("  {:<24} {:<20} {:<20}", "", "4KB Pages", "2MB HugePages");
    println!("  {}", "─".repeat(64));
    println!("  {:<24} {:<20} {:<20}", "Pages:", normal_pages, huge_pages);
    println!("  {:<24} {:<20} {:<20}", "Faults:",
        result_4k.stats.pages_faulted, result_2m.stats.pages_faulted);
    println!("  {:<24} {:<20} {:<20}", "Seal:",
        format!("{} ms", seal_4k_ms), format!("{} ms", seal_2m_ms));
    println!("  {:<24} {:<20} {:<20}", "Decrypt:",
        format!("{} ms", decrypt_4k_ms), format!("{} ms", decrypt_2m_ms));
    println!("  {:<24} {:<20} {:<20}", "Throughput:",
        format!("{:.0} MB/s", throughput_4k), format!("{:.0} MB/s", throughput_2m));
    println!("  {:<24} {:<20} {:<20}", "Compression:",
        format!("{:.1}x", sealed_4k.compression_ratio),
        format!("{:.1}x", sealed_2m.compression_ratio));
    println!("  {:<24} {:<20} {:<20}", "Encrypted storage:",
        format!("{} KB", sealed_4k.total_encrypted / 1024),
        format!("{} KB", sealed_2m.total_encrypted / 1024));

    if !lat_4k.is_empty() && !lat_2m.is_empty() {
        println!("  {:<24} {:<20} {:<20}", "p50:",
            format_ns(percentile(&lat_4k, 50.0)),
            format_ns(percentile(&lat_2m, 50.0)));
        println!("  {:<24} {:<20} {:<20}", "p99:",
            format_ns(percentile(&lat_4k, 99.0)),
            format_ns(percentile(&lat_2m, 99.0)));
    }

    let speedup = if decrypt_2m_ms > 0 {
        decrypt_4k_ms as f64 / decrypt_2m_ms as f64
    } else { 0.0 };

    println!("  {}", "─".repeat(64));
    println!("  {:<24} {:.1}x", "Speedup:", speedup);
    println!("  {:<24} {}x", "TLB reduction:", normal_pages / huge_pages);
    println!("  ══════════════════════════════════════════════════════════════");
    println!();

    // Checksum verification
    if checksum_4k == checksum_2m {
        println!("  ✓ Checksums match — 4KB en 2MB leveren identieke data");
    } else {
        println!("  ✗ Checksum mismatch! 4KB={:016x} 2MB={:016x}", checksum_4k, checksum_2m);
    }

    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  HUGEPAGE SHUTTLE COMPLEET");
    println!();
    println!("  2MB pages: minder faults, minder TLB druk, betere compressie.");
    println!("  De CPU doet meer werk per fault, maar minder faults totaal.");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
}

fn find_largest_blob(dir: &str, min_size: u64) -> Option<String> {
    let mut largest: Option<(String, u64)> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                let size = meta.len();
                if size > min_size {
                    // Prefer the ~19GB model (Q4_K_M)
                    if size > 15_000_000_000 && size < 25_000_000_000 {
                        return Some(entry.path().to_string_lossy().to_string());
                    }
                    if largest.as_ref().map_or(true, |(_, s)| size > *s) {
                        largest = Some((entry.path().to_string_lossy().to_string(), size));
                    }
                }
            }
        }
    }
    largest.map(|(p, _)| p)
}

fn read_file_pages(path: &str, total_bytes: usize, page_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(path).expect("cannot open file");
    let num_pages = total_bytes / page_size;
    let mut pages = Vec::with_capacity(num_pages);

    for _ in 0..num_pages {
        let mut page = vec![0u8; page_size];
        let bytes_read = file.read(&mut page).unwrap_or(0);
        if bytes_read < page_size {
            page[bytes_read..].fill(0);
        }
        pages.push(page);
    }
    pages
}
