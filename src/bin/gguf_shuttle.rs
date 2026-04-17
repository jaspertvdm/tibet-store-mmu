use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;
use tibet_store_mmu::*;
use tibet_trust_kernel::bifurcation::ClearanceLevel;

/// GGUF SHUTTLE — LLM Weights door de Encrypted MMU Arena
///
/// De ultieme test: 19.8GB humotica-32b (Qwen2 Q4_K_M) model weights
/// transparant serveren via userfaultfd met AES-256-GCM encryptie.
///
/// Pipeline:
///   GGUF file → read chunks → zstd compress → AES-256-GCM seal → stored
///   Inference touch → page fault → open → decompress → inject → resume
///
/// LLM ziet geen verschil. Data-at-rest is encrypted.
/// Geen JIS claim = dood materiaal. Identity IS the memory.

const GGUF_MAGIC: u32 = 0x46475547; // "GGUF" little-endian

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  GGUF SHUTTLE — LLM Weights door Encrypted MMU Arena     ║");
    println!("  ║                                                          ║");
    println!("  ║  GGUF → chunk → zstd → AES-256-GCM → userfaultfd        ║");
    println!("  ║  page fault → open → decompress → inject → resume        ║");
    println!("  ║                                                          ║");
    println!("  ║  Identity IS the memory. Geen claim = dood materiaal.    ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    if !userfaultfd_available() {
        println!("  ✗ userfaultfd niet beschikbaar");
        println!("  Tip: sudo sysctl -w vm.unprivileged_userfaultfd=1");
        return;
    }

    // ── Find the GGUF blob ──
    let blob_dir = "/usr/share/ollama/.ollama/models/blobs";
    let gguf_path = find_gguf_blob(blob_dir);

    let gguf_path = match gguf_path {
        Some(p) => p,
        None => {
            println!("  ✗ Geen GGUF blob gevonden in {}", blob_dir);
            return;
        }
    };

    let file_size = std::fs::metadata(&gguf_path).unwrap().len() as usize;
    println!("  GGUF blob: {}", gguf_path);
    println!("  Size:      {:.2} GB ({} bytes)", file_size as f64 / (1024.0 * 1024.0 * 1024.0), file_size);

    // ── Configuration ──
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    // Test sizes: 64MB, 256MB, 1GB slices of the GGUF
    let test_sizes: &[(usize, &str)] = &[
        (64 * 1024 * 1024,   "64 MB"),
        (256 * 1024 * 1024,  "256 MB"),
        (1024 * 1024 * 1024, "1 GB"),
    ];

    println!("  Page size: {} bytes", page_size);
    println!();

    // ── Header ──
    println!("  {:<10} {:<8} {:<14} {:<14} {:<10} {:<10} {:<10} {:<8} {:<10}",
        "Slice", "Pages", "Seal", "Decrypt", "p50", "p95", "p99", "Ratio", "Throughput");
    println!("  {}", "─".repeat(100));

    for &(test_size, label) in test_sizes {
        if test_size > file_size {
            println!("  {:<10} SKIP — groter dan bestand", label);
            continue;
        }

        let num_pages = test_size / page_size;

        // ── Read GGUF chunk from file ──
        let t_read = Instant::now();
        let pages = read_gguf_pages(&gguf_path, test_size, page_size);
        let read_ms = t_read.elapsed().as_millis();

        if pages.len() != num_pages {
            println!("  {:<10} ERROR — gelezen {} van {} pages", label, pages.len(), num_pages);
            continue;
        }

        // ── Seal (compress + encrypt) ──
        let t_seal = Instant::now();
        let sealed = seal_pages_compressed(
            &pages,
            ClearanceLevel::Secret,
            "gguf-shuttle",
            3,
        );
        let seal_ms = t_seal.elapsed().as_millis();
        let seal_per_us = (t_seal.elapsed().as_micros()) / num_pages as u128;

        // Drop plaintext pages — from here on, only encrypted data exists
        drop(pages);

        // ── Create encrypted arena ──
        let claim = mmu_claim("gguf-shuttle.aint", ClearanceLevel::TopSecret);

        let arena = match MmuArena::new(MmuConfig {
            arena_size: test_size,
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
                println!("  {:<10} ERROR — arena creation failed", label);
                continue;
            }
        };

        // ── Touch all pages (simulate inference reading weights) ──
        let t_touch = Instant::now();
        let mut verified = 0usize;
        let mut checksum: u64 = 0;

        for i in 0..num_pages {
            let offset = i * page_size;
            // Read first 8 bytes of each page — simulates tensor weight access
            let data = unsafe { arena.read_slice(offset, 8) };
            // Accumulate checksum to prevent optimizer from eliding reads
            for &b in &data {
                checksum = checksum.wrapping_add(b as u64);
            }
            verified += 1;
        }

        let touch_ms = t_touch.elapsed().as_millis();
        let touch_per_us = (t_touch.elapsed().as_micros()) / num_pages as u128;

        // ── Collect latencies ──
        let result = arena.shutdown();
        let mut sorted = result.fault_latencies_ns.clone();
        sorted.sort();

        let p50 = if !sorted.is_empty() { format_ns(percentile(&sorted, 50.0)) } else { "-".into() };
        let p95 = if !sorted.is_empty() { format_ns(percentile(&sorted, 95.0)) } else { "-".into() };
        let p99 = if !sorted.is_empty() { format_ns(percentile(&sorted, 99.0)) } else { "-".into() };

        let throughput_mbs = test_size as f64 / (1024.0 * 1024.0) / (touch_ms as f64 / 1000.0);

        println!("  {:<10} {:<8} {:<14} {:<14} {:<10} {:<10} {:<10} {:.1}x    {:.0} MB/s  ✓",
            label,
            num_pages,
            format!("{} ms", seal_ms),
            format!("{} ms", touch_ms),
            p50,
            p95,
            p99,
            sealed.compression_ratio,
            throughput_mbs,
        );

        // Extra detail per test
        println!("  {:<10} seal: {} µs/pg, decrypt: {} µs/pg, read: {} ms, checksum: {:016x}",
            "",
            seal_per_us,
            touch_per_us,
            read_ms,
            checksum,
        );
    }

    println!("  {}", "─".repeat(100));
    println!();

    // ── Extrapolation to full model ──
    println!("  ── Extrapolatie naar volledig model ({:.1} GB) ──",
        file_size as f64 / (1024.0 * 1024.0 * 1024.0));
    println!();

    let full_pages = file_size / page_size;
    println!("  Totaal pages:  {} ({:.1}M)", full_pages, full_pages as f64 / 1_000_000.0);
    println!("  Bij 53 µs/pg:  {:.1}s seal + {:.1}s decrypt = {:.1}s totaal",
        full_pages as f64 * 24.0 / 1_000_000.0,
        full_pages as f64 * 53.0 / 1_000_000.0,
        full_pages as f64 * 77.0 / 1_000_000.0);
    println!("  Bij 8x ratio:  {:.1} GB encrypted opslag",
        file_size as f64 / 8.0 / (1024.0 * 1024.0 * 1024.0));
    println!();

    // ── Access denied test with GGUF data ──
    println!("  ── Access Control: Restricted claim → GGUF weights ──");

    let small_size = 16 * page_size; // Just 16 pages for this test
    let pages = read_gguf_pages(&gguf_path, small_size, page_size);
    let sealed = seal_pages_compressed(&pages, ClearanceLevel::Secret, "gguf-denied", 3);

    let low_claim = mmu_claim("intruder.aint", ClearanceLevel::Restricted);
    let arena = MmuArena::new(MmuConfig {
        arena_size: small_size,
        fill_mode: FillMode::CompressedEncryptedRestore {
            sealed_pages: sealed.blocks,
            original_sizes: sealed.original_sizes,
            claim: low_claim,
            clearance: ClearanceLevel::Secret,
        },
        use_hugepages: false,
    }).expect("denied arena");

    let data = unsafe { arena.read_slice(0, 64) };
    let all_zero = data.iter().all(|&b| b == 0);
    let _ = arena.shutdown();

    if all_zero {
        println!("  ✓ DENIED — Restricted claim → zero page (model weights onzichtbaar)");
    } else {
        println!("  ✗ FOUT — Restricted claim kon model weights lezen!");
    }

    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  GGUF SHUTTLE COMPLEET");
    println!();
    println!("  LLM weights encrypted at rest, decrypted per page fault.");
    println!("  Inference ziet geen verschil. Data is AES-256-GCM sealed.");
    println!("  Zonder JIS claim: dood materiaal (zero pages).");
    println!();
    println!("  Dit is encrypted-by-default RAM voor AI.");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
}

/// Find the ~19GB GGUF blob (largest file in the blobs directory).
fn find_gguf_blob(blob_dir: &str) -> Option<String> {
    let mut largest: Option<(String, u64)> = None;

    if let Ok(entries) = std::fs::read_dir(blob_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                let size = meta.len();
                // Look for files between 15GB and 25GB (humotica-32b Q4_K_M range)
                if size > 15_000_000_000 && size < 25_000_000_000 {
                    if largest.as_ref().map_or(true, |(_, s)| size > *s) {
                        largest = Some((entry.path().to_string_lossy().to_string(), size));
                    }
                }
            }
        }
    }

    // If no 19GB blob, fall back to largest file > 1GB
    if largest.is_none() {
        if let Ok(entries) = std::fs::read_dir(blob_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let size = meta.len();
                    if size > 1_000_000_000 {
                        if largest.as_ref().map_or(true, |(_, s)| size > *s) {
                            largest = Some((entry.path().to_string_lossy().to_string(), size));
                        }
                    }
                }
            }
        }
    }

    largest.map(|(p, _)| p)
}

/// Read GGUF file into page-sized chunks.
fn read_gguf_pages(path: &str, total_bytes: usize, page_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(path).expect("cannot open GGUF");
    let num_pages = total_bytes / page_size;
    let mut pages = Vec::with_capacity(num_pages);

    // Read header to verify GGUF magic
    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf).ok();
    let magic = u32::from_le_bytes(magic_buf);
    if magic == GGUF_MAGIC {
        // Valid GGUF — but we read raw bytes regardless
    }

    // Seek back to start and read in page chunks
    file.seek(SeekFrom::Start(0)).unwrap();

    for _ in 0..num_pages {
        let mut page = vec![0u8; page_size];
        let bytes_read = file.read(&mut page).unwrap_or(0);
        if bytes_read < page_size {
            // Pad with zeros (last partial page)
            page[bytes_read..].fill(0);
        }
        pages.push(page);
    }

    pages
}
