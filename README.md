# jentfish

A high-throughput cryptographic random data generator built on **Threefish-1024** (AVX-512 intrinsics) in counter mode.

jentfish uses [avxfish](https://github.com/qnfm/avxfish) — an AVX-512 implementation of the Threefish-1024 block cipher — to generate cryptographically strong pseudorandom data at hundreds of MiB/s per core.

## Features

- **Threefish-1024 CTR mode** — 1024-bit block cipher in counter mode for high-bandwidth PRNG
- **AVX-512 accelerated** — leverages AVX-512F intrinsics for maximum throughput
- **Parallel workers** — scales across all available CPU cores
- **Append mode** — incrementally grows output files with block-aligned writes
- **128-byte key from `crypto/rand`** — fresh key generated per invocation

## Requirements

- Linux amd64 with AVX-512F support
- Go 1.22+ (uses cgo)
- C++17 compiler (g++ or clang++) with AVX-512 support

## Building

```bash
# 1. Clone with submodule
git clone --recurse-submodules https://github.com/qnfm/jentfish.git
cd jentfish

# 2. Build the avxfish static library
cd third_party/avxfish
make lib
cd ../..

# 3. Build jentfish
CGO_ENABLED=1 go build ./cmd/jentfish/
```

## Usage

```bash
# Generate 1 GiB of random data (default)
./jentfish -out output.bin -size 1GiB

# Generate 100 MiB with 4 workers
./jentfish -out output.bin -size 100MiB -workers 4

# Append 512 MiB to existing file
./jentfish -out existing.bin -size 512MiB
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-out` | `out.bin` | Output file path |
| `-size` | `1GiB` | Bytes to generate (supports B, KB, MB, GB, TB, KiB, MiB, GiB, TiB) |
| `-workers` | `NumCPU` | Number of parallel worker goroutines |
| `-buf-blocks` | `8192` | Number of 128-byte blocks per work unit |

## Architecture

```
┌─────────────────────────────────────────────┐
│  jentfish CLI                               │
│  cmd/jentfish/main.go                       │
├─────────────────────────────────────────────┤
│  Go binding (cgo)                           │
│  internal/avxfish/avxfish.go                │
│  - NewCipher / FillCounter / Close          │
│  - CTR mode over Threefish-1024 blocks      │
├─────────────────────────────────────────────┤
│  avxfish C++ library (git submodule)        │
│  third_party/avxfish/                       │
│  - AVX-512 intrinsics Threefish-1024        │
│  - Key schedule, encrypt, decrypt           │
│  - Runtime CPUID/XGETBV detection           │
└─────────────────────────────────────────────┘
```

## Submodule

jentfish depends on avxfish via git submodule (tracking the `int` branch):

```bash
# After cloning, initialize submodule
git submodule update --init --recursive

# Update to latest int branch
git submodule update --remote third_party/avxfish
```

## Performance

On AVX-512 capable hardware, typical throughput is **400–600 MiB/s** per core in CTR mode with parallel workers saturating available cores.

## License

Apache 2.0 — see [LICENSE](LICENSE).
