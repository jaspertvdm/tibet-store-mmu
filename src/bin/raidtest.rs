use std::time::Instant;
use tibet_trust_kernel::bifurcation::ClearanceLevel;
use tibet_trust_kernel::ram_raid::{RamRaidController, RaidConfig, RaidStats, FaultResult, EvictionResult};

/// RAIDTEST — RAM RAID-0 Controller met Encrypted Eviction
///
/// Tests:
///   1. Controller creatie (32MB arena, 2MB blocks)
///   2. Write workload → blocks worden resident + dirty
///   3. Pressure → LRU eviction → compress + seal + store
///   4. Read na eviction → fault → restore → verify
///   5. Remote RAM B simulatie (RAID-0 striping)
///   6. Stats + throughput rapportage

fn main() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════╗");
    println!("  ║  RAIDTEST — RAM RAID-0 Controller                        ║");
    println!("  ║                                                          ║");
    println!("  ║  Write → Pressure → Evict → Fault → Restore → Verify    ║");
    println!("  ║  RAID-0: even blocks → RAM A, odd → RAM B               ║");
    println!("  ╚═══════════════════════════════════════════════════════════╝");
    println!();

    // ── Test 1: Local-only RAID (alle blocks resident) ──
    println!("  ── Test 1: Local-only RAID Controller ──");
    println!();

    let arena_size = 32 * 1024 * 1024; // 32MB
    let config = RaidConfig::new(arena_size, "raidtest", "root_idd.aint");
    let mut controller = RamRaidController::new(config);

    let stats = controller.stats();
    println!("  Arena:     {} MB ({} blocks × {} MB)",
        stats.arena_size / (1024 * 1024),
        stats.block_count,
        stats.block_size / (1024 * 1024));
    println!("  RAM A:     {} blocks (even — local)", stats.ram_a_blocks);
    println!("  RAM B:     {} blocks (odd — remote)", stats.ram_b_blocks);
    println!("  Resident:  {}/{} (max)", stats.resident_blocks, stats.max_resident);
    println!("  Virgin:    {} blocks", stats.virgin_blocks);
    println!();

    // ── Test 2: Write workload ──
    println!("  ── Test 2: Write workload (fill all blocks) ──");

    let t0 = Instant::now();
    for i in 0..stats.block_count {
        controller.simulate_write(i);
    }
    let write_us = t0.elapsed().as_micros();

    let stats2 = controller.stats();
    println!("  Written:   {} blocks in {} µs ({} µs/block)",
        stats2.block_count, write_us, write_us / stats2.block_count as u128);
    println!("  Resident:  {} (all)", stats2.resident_blocks);
    println!("  Dirty:     {} (all)", stats2.dirty_blocks);
    println!();

    // ── Test 3: Pressure test — limit resident, force eviction ──
    println!("  ── Test 3: Eviction under pressure (max 8 of 16 resident) ──");

    let arena_size = 32 * 1024 * 1024;
    let config = RaidConfig::new(arena_size, "pressure-test", "root_idd.aint")
        .with_max_resident(8); // Only 8 of 16 blocks can be resident

    let mut controller = RamRaidController::new(config);

    // Write all 16 blocks (makes them resident + dirty)
    for i in 0..16 {
        controller.simulate_write(i);
    }

    let stats3a = controller.stats();
    println!("  Before eviction: {} resident, {} dirty", stats3a.resident_blocks, stats3a.dirty_blocks);

    // Now read block 0 — it's resident, no fault
    let t0 = Instant::now();
    let read_result = controller.simulate_read(0);
    let read_us = t0.elapsed().as_micros();

    match &read_result {
        FaultResult::AlreadyResident { .. } => println!("  Read block 0: RESIDENT ({} µs)", read_us),
        _ => println!("  Read block 0: {:?}", read_result),
    }

    // Force proactive eviction
    let t0 = Instant::now();
    let evict_results = controller.proactive_evict();
    let evict_us = t0.elapsed().as_micros();

    let evicted_count = evict_results.len();
    let mut local_evictions = 0;
    let mut dropped = 0;

    for r in &evict_results {
        match r {
            EvictionResult::EvictedLocal { .. } => local_evictions += 1,
            EvictionResult::Dropped { .. } => dropped += 1,
            _ => {}
        }
    }

    println!("  Proactive eviction: {} blocks in {} µs", evicted_count, evict_us);
    println!("    Evicted (compress+seal): {}", local_evictions);
    println!("    Dropped (clean): {}", dropped);

    let stats3b = controller.stats();
    println!("  After eviction: {} resident, {} dirty, {} local-stored",
        stats3b.resident_blocks, stats3b.dirty_blocks, stats3b.local_evicted);

    // Now read an evicted block — triggers fault → restore
    let evicted_idx = controller.stats().block_count - 1; // Last block likely evicted
    let t0 = Instant::now();
    let fault_result = controller.simulate_read(evicted_idx);
    let fault_us = t0.elapsed().as_micros();

    match &fault_result {
        FaultResult::RestoredLocal { block_index, total_us, .. } =>
            println!("  Fault restore block {}: {} µs (sim pipeline)", block_index, total_us),
        FaultResult::ZeroFilled { block_index, .. } =>
            println!("  Block {} was virgin → zero fill", block_index),
        FaultResult::AlreadyResident { block_index } =>
            println!("  Block {} still resident (not evicted)", block_index),
        _ => println!("  Fault result: {:?}", fault_result),
    }

    println!();

    // ── Test 4: Remote RAM B simulation ──
    println!("  ── Test 4: RAID-0 met Remote RAM B ──");

    let config = RaidConfig::new(arena_size, "raid-remote", "root_idd.aint")
        .with_remote_ram_b("dl360.aint", "http://192.168.4.84:9000")
        .with_max_resident(4); // Aggressive: only 4 of 16 blocks

    let mut controller = RamRaidController::new(config);

    // Write all blocks
    for i in 0..16 {
        controller.simulate_write(i);
    }

    // Force eviction to get remote transfers
    let t0 = Instant::now();
    let evict_results = controller.proactive_evict();
    let evict_us = t0.elapsed().as_micros();

    let mut remote_evictions = 0;
    let mut local_evictions = 0;
    for r in &evict_results {
        match r {
            EvictionResult::EvictedRemote { .. } => remote_evictions += 1,
            EvictionResult::EvictedLocal { .. } => local_evictions += 1,
            _ => {}
        }
    }

    println!("  Evicted: {} total ({} local, {} remote) in {} µs",
        evict_results.len(), local_evictions, remote_evictions, evict_us);

    let stats4 = controller.stats();
    println!("  Resident: {}, Local stored: {}, Remote stored: {}",
        stats4.resident_blocks, stats4.local_evicted, stats4.remote_evicted);

    // Read a remote-evicted block — simulates network fetch
    for i in 0..16 {
        let result = controller.simulate_read(i);
        if let FaultResult::RestoredRemote { block_index, fetch_us, total_us, .. } = &result {
            println!("  Remote restore block {}: fetch {} µs, total {} µs",
                block_index, fetch_us, total_us);
            break; // Just show one
        }
    }

    println!();

    // ── Test 5: Production mode (echte userfaultfd) ──
    println!("  ── Test 5: Production Mode (userfaultfd + RAM RAID) ──");

    let config = RaidConfig::new(
        8 * 1024 * 1024, // 8MB — 4 blocks
        "production-test",
        "root_idd.aint",
    );

    let controller = RamRaidController::new(config);

    match controller.start_production() {
        Some(active) => {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
            println!("  ✓ MMU trap active op {:?}", active.arena_ptr);

            // Touch first page of each 2MB block
            let block_size = 2 * 1024 * 1024;
            let num_blocks = 4;

            let t0 = Instant::now();
            for i in 0..num_blocks {
                let offset = i * block_size;
                let ptr = unsafe { (active.arena_ptr as *const u8).add(offset) };
                let byte = unsafe { std::ptr::read_volatile(ptr) };
                // The fault handler injects TIBET metadata
                let slice = unsafe { std::slice::from_raw_parts(ptr, 40.min(page_size)) };
                let text = String::from_utf8_lossy(slice);
                println!("  Block {}: first 40 bytes = {:?}", i, &text[..40.min(text.len())]);
            }
            let touch_us = t0.elapsed().as_micros();

            println!("  Touched {} blocks in {} µs ({} µs/block)",
                num_blocks, touch_us, touch_us / num_blocks as u128);

            let prod_stats = active.controller.lock().unwrap().stats();
            println!("  Faults: {}, Zero pages: {}",
                prod_stats.faults_handled, prod_stats.zero_pages_served);

            active.shutdown();
            println!("  ✓ Shutdown clean");
        }
        None => {
            println!("  ✗ userfaultfd niet beschikbaar (sudo sysctl -w vm.unprivileged_userfaultfd=1)");
        }
    }

    println!();

    // ── Final stats ──
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  RAIDTEST COMPLEET");
    println!();
    println!("  RAM RAID-0: transparante geheugen-virtualisatie");
    println!("  Even blocks → RAM A (local), Odd → RAM B (remote)");
    println!("  LRU eviction: coldest block → compress → seal → store");
    println!("  Fault restore: lookup → fetch → verify → decompress → inject");
    println!();
    println!("  Volgende stap: bifurcation integratie");
    println!("  simulate_* → AES-256-GCM + Ed25519 (echte crypto)");
    println!("  Dan: echte TCP/QUIC transport P520 ↔ DL360");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
}
