//go:build linux && amd64 && cgo

package avxfish

/*
#cgo CFLAGS: -O3 -mavx512f -mavx512vl -I${SRCDIR}/../../third_party/avxfish/include
#cgo LDFLAGS: -L${SRCDIR}/../../third_party/avxfish/lib -lavxfish
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "avxfish.h"

static int aligned_alloc64(void **p, size_t n) {
	return posix_memalign(p, 64, n);
}

static void aligned_free64(void *p) {
	free(p);
}

// key:   128 bytes
// tweak: 16 bytes
// out:   21 * 16 uint64_t
static int make_subkeys(const void *key, const void *tweak, uint64_t *out) {
	if (((uintptr_t)out & 63) != 0) return -1;
	threefish1024_key_schedule(key, tweak, out);
	return 0;
}

// Fill N blocks in Threefish-1024 CTR mode.
// scratch must point to a reusable 64-byte aligned 128-byte buffer owned by the caller.
static int gen_counter_mode(
	uint8_t *out,
	size_t blocks,
	uint64_t counter_lo,
	uint64_t counter_hi,
	const uint64_t *subkeys,
	void *scratch
) {
	if (((uintptr_t)scratch & 63) != 0) return -2;

	for (size_t i = 0; i < blocks; i++) {
		memset(scratch, 0, 128);

		uint64_t lo = counter_lo + (uint64_t)i;
		uint64_t hi = counter_hi;
		if (lo < counter_lo) hi++;

		((uint64_t*)scratch)[0] = lo;
		((uint64_t*)scratch)[1] = hi;

		avxfish(scratch, subkeys);
		memcpy(out + i * 128, scratch, 128);
	}

	return 0;
}
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

const (
	BlockSize  = 128
	KeySize    = 128
	TweakSize  = 16
	subkeyU64s = 21 * 16
)

type Cipher struct {
	subkeys *C.uint64_t
	scratch unsafe.Pointer
}

func NewCipher(key [KeySize]byte, tweak [TweakSize]byte) (*Cipher, error) {
	var subkeys unsafe.Pointer
	if rc := C.aligned_alloc64(&subkeys, C.size_t(subkeyU64s*8)); rc != 0 || subkeys == nil {
		return nil, fmt.Errorf("aligned subkey allocation failed: rc=%d", int(rc))
	}

	var scratch unsafe.Pointer
	if rc := C.aligned_alloc64(&scratch, C.size_t(BlockSize)); rc != 0 || scratch == nil {
		C.aligned_free64(subkeys)
		return nil, fmt.Errorf("aligned scratch allocation failed: rc=%d", int(rc))
	}

	if rc := C.make_subkeys(
		unsafe.Pointer(&key[0]),
		unsafe.Pointer(&tweak[0]),
		(*C.uint64_t)(subkeys),
	); rc != 0 {
		C.aligned_free64(scratch)
		C.aligned_free64(subkeys)
		return nil, fmt.Errorf("make_subkeys failed: rc=%d", int(rc))
	}

	return &Cipher{
		subkeys: (*C.uint64_t)(subkeys),
		scratch: scratch,
	}, nil
}

func (c *Cipher) Close() {
	if c.scratch != nil {
		C.aligned_free64(c.scratch)
		c.scratch = nil
	}
	if c.subkeys != nil {
		C.aligned_free64(unsafe.Pointer(c.subkeys))
		c.subkeys = nil
	}
}

func (c *Cipher) FillCounter(dst []byte, counterLo, counterHi uint64) error {
	if len(dst) == 0 {
		return nil
	}
	if len(dst)%BlockSize != 0 {
		return fmt.Errorf("buffer length %d is not a multiple of block size %d", len(dst), BlockSize)
	}
	if c.subkeys == nil || c.scratch == nil {
		return fmt.Errorf("cipher closed")
	}

	rc := C.gen_counter_mode(
		(*C.uint8_t)(unsafe.Pointer(&dst[0])),
		C.size_t(len(dst)/BlockSize),
		C.uint64_t(counterLo),
		C.uint64_t(counterHi),
		c.subkeys,
		c.scratch,
	)
	if rc != 0 {
		return fmt.Errorf("gen_counter_mode failed: rc=%d", int(rc))
	}
	return nil
}

func KeyFromEntropy(r io.Reader) ([KeySize]byte, error) {
	var key [KeySize]byte
	_, err := io.ReadFull(r, key[:])
	return key, err
}

func ZeroTweak() [TweakSize]byte {
	return [TweakSize]byte{}
}
