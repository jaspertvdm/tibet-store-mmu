use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use tibet_store_mmu::*;
use tibet_trust_kernel::bifurcation::ClearanceLevel;

// ═══════════════════════════════════════════════════════════════
// CRITERION BENCHMARKS — Meetdiscipline voor Trust Kernel MMU
//
// Per commit: herhaalbare p50/p95/p99, regressiedetectie,
// HTML reports in target/criterion/
//
// Benchmarks:
//   1. seal_pages — AES-256-GCM sealing throughput
//   2. seal_pages_compressed — zstd + AES-256-GCM pipeline
//   3. page_fault_encrypted — single page fault + decrypt
//   4. page_fault_compressed — single page fault + decrypt + decompress
//   5. scaling — throughput at 64/256/1024/4096 pages
//   6. access_denied — zero page injection on bad clearance
// ═══════════════════════════════════════════════════════════════

fn make_test_pages(num_pages: usize, page_size: usize) -> Vec<Vec<u8>> {
    (0..num_pages)
        .map(|i| {
            let mut page = vec![0u8; page_size];
            let text = format!(
                "PAGE[{:06}] Criterion benchmark data — encrypted at rest, \
                 decrypted on fault. AES-256-GCM + zstd. Sequence: {}.",
                i, i * 7 + 42
            );
            let bytes = text.as_bytes();
            page[..bytes.len()].copy_from_slice(bytes);
            for j in 256..512.min(page_size) {
                page[j] = ((i + j) % 256) as u8;
            }
            page
        })
        .collect()
}

// ── Benchmark 1: Seal throughput (encrypt-only) ──
fn bench_seal(c: &mut Criterion) {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let mut group = c.benchmark_group("seal");
    for num_pages in [64, 256, 1024] {
        let pages = make_test_pages(num_pages, page_size);
        group.throughput(Throughput::Bytes((num_pages * page_size) as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_only", num_pages),
            &pages,
            |b, pages| {
                b.iter(|| {
                    seal_pages(pages, ClearanceLevel::Secret, "criterion-seal")
                });
            },
        );
    }
    group.finish();
}

// ── Benchmark 2: Seal throughput (compressed + encrypted) ──
fn bench_seal_compressed(c: &mut Criterion) {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let mut group = c.benchmark_group("seal_compressed");
    for num_pages in [64, 256, 1024] {
        let pages = make_test_pages(num_pages, page_size);
        group.throughput(Throughput::Bytes((num_pages * page_size) as u64));
        group.bench_with_input(
            BenchmarkId::new("zstd3_aes256gcm", num_pages),
            &pages,
            |b, pages| {
                b.iter(|| {
                    seal_pages_compressed(pages, ClearanceLevel::Secret, "criterion-comp", 3)
                });
            },
        );
    }
    group.finish();
}

// ── Benchmark 3: Single encrypted page fault (end-to-end) ──
fn bench_fault_encrypted(c: &mut Criterion) {
    if !userfaultfd_available() {
        eprintln!("SKIP: userfaultfd niet beschikbaar");
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let num_pages = 16; // Small arena, we measure per-fault

    let mut group = c.benchmark_group("fault_encrypted");
    group.sample_size(30); // userfaultfd needs thread setup per iteration
    group.throughput(Throughput::Bytes((num_pages * page_size) as u64));

    let pages = make_test_pages(num_pages, page_size);

    group.bench_function("encrypt_only", |b| {
        b.iter(|| {
            let sealed = seal_pages(&pages, ClearanceLevel::Secret, "criterion-fault");
            let claim = mmu_claim("criterion.aint", ClearanceLevel::TopSecret);

            let arena = MmuArena::new(MmuConfig {
                arena_size: num_pages * page_size,
                fill_mode: FillMode::EncryptedRestore {
                    sealed_pages: sealed,
                    claim,
                    clearance: ClearanceLevel::Secret,
                },
                use_hugepages: false,
            }).expect("arena");

            for i in 0..num_pages {
                unsafe { arena.read_slice(i * page_size, 40); }
            }

            arena.shutdown()
        });
    });

    group.finish();
}

// ── Benchmark 4: Single compressed+encrypted page fault ──
fn bench_fault_compressed(c: &mut Criterion) {
    if !userfaultfd_available() {
        eprintln!("SKIP: userfaultfd niet beschikbaar");
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let num_pages = 16;

    let mut group = c.benchmark_group("fault_compressed");
    group.sample_size(30);
    group.throughput(Throughput::Bytes((num_pages * page_size) as u64));

    let pages = make_test_pages(num_pages, page_size);

    group.bench_function("zstd3_aes256gcm", |b| {
        b.iter(|| {
            let sealed = seal_pages_compressed(
                &pages, ClearanceLevel::Secret, "criterion-cfault", 3
            );
            let claim = mmu_claim("criterion.aint", ClearanceLevel::TopSecret);

            let arena = MmuArena::new(MmuConfig {
                arena_size: num_pages * page_size,
                fill_mode: FillMode::CompressedEncryptedRestore {
                    sealed_pages: sealed.blocks,
                    original_sizes: sealed.original_sizes,
                    claim,
                    clearance: ClearanceLevel::Secret,
                },
                use_hugepages: false,
            }).expect("arena");

            for i in 0..num_pages {
                unsafe { arena.read_slice(i * page_size, 40); }
            }

            arena.shutdown()
        });
    });

    group.finish();
}

// ── Benchmark 5: Scaling — throughput at different arena sizes ──
fn bench_scaling(c: &mut Criterion) {
    if !userfaultfd_available() {
        eprintln!("SKIP: userfaultfd niet beschikbaar");
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let mut group = c.benchmark_group("scaling");
    group.sample_size(20);

    for num_pages in [64, 256, 1024, 4096] {
        let pages = make_test_pages(num_pages, page_size);
        group.throughput(Throughput::Bytes((num_pages * page_size) as u64));

        group.bench_with_input(
            BenchmarkId::new("compressed_encrypted", num_pages),
            &num_pages,
            |b, &np| {
                b.iter(|| {
                    let sealed = seal_pages_compressed(
                        &pages, ClearanceLevel::Secret, "criterion-scale", 3
                    );
                    let claim = mmu_claim("criterion-scale.aint", ClearanceLevel::TopSecret);

                    let arena = MmuArena::new(MmuConfig {
                        arena_size: np * page_size,
                        fill_mode: FillMode::CompressedEncryptedRestore {
                            sealed_pages: sealed.blocks,
                            original_sizes: sealed.original_sizes,
                            claim,
                            clearance: ClearanceLevel::Secret,
                        },
                        use_hugepages: false,
                    }).expect("arena");

                    for i in 0..np {
                        unsafe { arena.read_slice(i * page_size, 40); }
                    }

                    arena.shutdown()
                });
            },
        );
    }

    group.finish();
}

// ── Benchmark 6: Access denied — zero page injection speed ──
fn bench_access_denied(c: &mut Criterion) {
    if !userfaultfd_available() {
        eprintln!("SKIP: userfaultfd niet beschikbaar");
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let num_pages = 16;
    let pages = make_test_pages(num_pages, page_size);

    let mut group = c.benchmark_group("access_denied");
    group.sample_size(30);

    group.bench_function("restricted_vs_secret", |b| {
        b.iter(|| {
            let sealed = seal_pages(&pages, ClearanceLevel::Secret, "criterion-denied");
            // Restricted claim trying to read Secret data → zero page
            let low_claim = mmu_claim("intruder.aint", ClearanceLevel::Restricted);

            let arena = MmuArena::new(MmuConfig {
                arena_size: num_pages * page_size,
                fill_mode: FillMode::EncryptedRestore {
                    sealed_pages: sealed,
                    claim: low_claim,
                    clearance: ClearanceLevel::Secret,
                },
                use_hugepages: false,
            }).expect("arena");

            for i in 0..num_pages {
                let data = unsafe { arena.read_slice(i * page_size, 16) };
                assert!(data.iter().all(|&b| b == 0), "should be dead material");
            }

            arena.shutdown()
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_seal,
    bench_seal_compressed,
    bench_fault_encrypted,
    bench_fault_compressed,
    bench_scaling,
    bench_access_denied,
);
criterion_main!(benches);
