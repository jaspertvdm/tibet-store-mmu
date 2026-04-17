# tibet-store-mmu

Transparent RAM virtualization via userfaultfd. Pages fault in from compressed archives, encrypted by default via [tibet-trust-kernel](https://crates.io/crates/tibet-trust-kernel) bifurcation.

## What it does

tibet-store-mmu uses Linux `userfaultfd` to intercept page faults on mmap'd regions and inject data from various sources — zero-fill, static payloads, compressed archives, or GGUF model files. All pages are encrypted at rest via AES-256-GCM.

```
App accesses virtual page → page fault → userfaultfd trap →
  fetch from .tza archive → decompress → bifurcation decrypt →
  inject into address space → app resumes transparently
```

## Three modes

| Mode | Description | Use case |
|------|-------------|----------|
| `ZeroFill` | Inject zero page | Virgin memory allocation |
| `StaticData` | Inject fixed payload | Redis-style cached data |
| `CompressedRestore` | Decompress .tza + inject | Production restore from snapshots |

## Binaries

| Binary | Description |
|--------|-------------|
| `spaceshuttle` | Full MMU illusion demo with metrics |
| `gguf-shuttle` | Load GGUF model files through userfaultfd pipeline |
| `hugepage-shuttle` | Huge page (2MB) transport demo |
| `scaletest` | Scale testing — measure fault rates under load |
| `raidtest` | RAID-0 striping test with remote transport |

## Install

```toml
[dependencies]
tibet-store-mmu = { git = "https://github.com/Humotica/tibet-store-mmu" }
```

Requires Linux with userfaultfd support (kernel 4.11+, or `sysctl vm.unprivileged_userfaultfd=1`).

## Relationship to tibet-trust-kernel

tibet-store-mmu is the **PoC that proved userfaultfd works** for transparent memory virtualization. The lessons learned here were incorporated into tibet-trust-kernel's `ram_raid` module and [tibet-dgx](https://github.com/Humotica/tibet-dgx) CLI for production cross-machine LLM inference.

## Part of TIBET

Built by [Humotica](https://humotica.com) for the [AInternet](https://ainternet.org).

## License

MIT
