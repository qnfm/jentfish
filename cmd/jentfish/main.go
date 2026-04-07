package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qnfm/jentfish/internal/avxfish"
)

const (
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
	TiB = 1024 * GiB
)

type job struct {
	blockIndex  uint64
	numBlocks   uint64
	writeOffset int64
	writeBytes  int
}

func parseSize(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mul := uint64(1)

	switch {
	case strings.HasSuffix(s, "TIB"):
		mul = TiB
		s = strings.TrimSuffix(s, "TIB")
	case strings.HasSuffix(s, "GIB"):
		mul = GiB
		s = strings.TrimSuffix(s, "GIB")
	case strings.HasSuffix(s, "MIB"):
		mul = MiB
		s = strings.TrimSuffix(s, "MIB")
	case strings.HasSuffix(s, "KIB"):
		mul = KiB
		s = strings.TrimSuffix(s, "KIB")
	case strings.HasSuffix(s, "TB"):
		mul = 1000 * 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GB"):
		mul = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mul = 1000 * 1000
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mul = 1000
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}

	var v float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%f", &v); err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("size must be non-negative")
	}
	return uint64(v * float64(mul)), nil
}

func roundUpToBlock(n uint64, block uint64) uint64 {
	if rem := n % block; rem != 0 {
		return n + (block - rem)
	}
	return n
}

func worker(
	id int,
	f *os.File,
	key [avxfish.KeySize]byte,
	tweak [avxfish.TweakSize]byte,
	jobs <-chan job,
	written *atomic.Uint64,
	errCh chan<- error,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	cipher, err := avxfish.NewCipher(key, tweak)
	if err != nil {
		select {
		case errCh <- fmt.Errorf("worker %d: avxfish init failed: %w", id, err):
		default:
		}
		return
	}
	defer cipher.Close()

	var buf []byte

	for j := range jobs {
		need := int(j.numBlocks * avxfish.BlockSize)
		if cap(buf) < need {
			buf = make([]byte, need)
		}
		buf = buf[:need]

		ctrLo := j.blockIndex
		ctrHi := uint64(0)

		if err := cipher.FillCounter(buf, ctrLo, ctrHi); err != nil {
			select {
			case errCh <- fmt.Errorf("worker %d: FillCounter failed at block %d: %w", id, j.blockIndex, err):
			default:
			}
			return
		}

		n, err := f.WriteAt(buf[:j.writeBytes], j.writeOffset)
		if err != nil {
			select {
			case errCh <- fmt.Errorf("worker %d: WriteAt failed at offset %d: %w", id, j.writeOffset, err):
			default:
			}
			return
		}
		if n != j.writeBytes {
			select {
			case errCh <- fmt.Errorf("worker %d: short write at offset %d: got %d want %d", id, j.writeOffset, n, j.writeBytes):
			default:
			}
			return
		}

		written.Add(uint64(n))
	}
}

func main() {
	var (
		outPath   = flag.String("out", "out.bin", "output file path")
		sizeStr   = flag.String("size", "1GiB", "bytes to append")
		bufBlocks = flag.Int("buf-blocks", 8192, "number of 128-byte blocks per job")
		workers   = flag.Int("workers", runtime.NumCPU(), "number of worker goroutines")
	)
	flag.Parse()

	if *bufBlocks <= 0 {
		fmt.Fprintln(os.Stderr, "buf-blocks must be > 0")
		os.Exit(1)
	}
	if *workers <= 0 {
		fmt.Fprintln(os.Stderr, "workers must be > 0")
		os.Exit(1)
	}

	total, err := parseSize(*sizeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "size parse error:", err)
		os.Exit(1)
	}
	if total == 0 {
		fmt.Fprintln(os.Stderr, "size must be > 0")
		os.Exit(1)
	}

	genTotal := roundUpToBlock(total, avxfish.BlockSize)
	totalBlocks := genTotal / avxfish.BlockSize

	key, err := avxfish.KeyFromEntropy(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read key from crypto/rand:", err)
		os.Exit(1)
	}
	tweak := avxfish.ZeroTweak()

	f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open output failed:", err)
		os.Exit(1)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stat failed:", err)
		os.Exit(1)
	}

	oldSize := uint64(fi.Size())
	baseOffset := roundUpToBlock(oldSize, avxfish.BlockSize)
	padding := baseOffset - oldSize
	finalSize := baseOffset + total

	if padding > 0 {
		if err := f.Truncate(int64(baseOffset)); err != nil {
			fmt.Fprintln(os.Stderr, "pad truncate failed:", err)
			os.Exit(1)
		}
	}

	if err := f.Truncate(int64(finalSize)); err != nil {
		fmt.Fprintln(os.Stderr, "final truncate failed:", err)
		os.Exit(1)
	}

	jobs := make(chan job, *workers*2)
	errCh := make(chan error, 1)

	var written atomic.Uint64
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i, f, key, tweak, jobs, &written, errCh, &wg)
	}

	start := time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Fprintf(
		os.Stderr,
		"old_size=%d padded_base=%d padding=%d append=%d gen_append=%d workers=%d buf_blocks=%d go=%s cpus=%d\n",
		oldSize, baseOffset, padding, total, genTotal, *workers, *bufBlocks, runtime.Version(), runtime.NumCPU(),
	)

	go func() {
		defer close(jobs)

		var blockIndex uint64
		for blockIndex < totalBlocks {
			nblocks := uint64(*bufBlocks)
			if remain := totalBlocks - blockIndex; remain < nblocks {
				nblocks = remain
			}

			relativeOffset := blockIndex * avxfish.BlockSize
			writeBytes := int(nblocks * avxfish.BlockSize)

			if remainReal := total - relativeOffset; uint64(writeBytes) > remainReal {
				writeBytes = int(remainReal)
			}

			j := job{
				blockIndex:  blockIndex,
				numBlocks:   nblocks,
				writeOffset: int64(baseOffset + relativeOffset),
				writeBytes:  writeBytes,
			}

			select {
			case jobs <- j:
			case err := <-errCh:
				fmt.Fprintln(os.Stderr, "generation failed:", err)
				return
			}

			blockIndex += nblocks
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for {
		select {
		case err := <-errCh:
			fmt.Fprintln(os.Stderr, "generation failed:", err)
			os.Exit(1)

		case <-done:
			if err := f.Sync(); err != nil {
				fmt.Fprintln(os.Stderr, "fsync failed:", err)
				os.Exit(1)
			}
			elapsed := time.Since(start).Seconds()
			finalWritten := written.Load()
			fmt.Fprintf(
				os.Stderr,
				"\rappended=%d bytes total (%.2f MiB/s), final_size=%d\n",
				finalWritten,
				float64(finalWritten)/MiB/elapsed,
				finalSize,
			)
			return

		case <-ticker.C:
			cur := written.Load()
			mbps := float64(cur) / MiB / time.Since(start).Seconds()
			fmt.Fprintf(os.Stderr, "\rappended=%d bytes (%.2f MiB/s)", cur, mbps)
		}
	}
}
