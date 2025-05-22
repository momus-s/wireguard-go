package device

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/poly1305"
)

func TestPoly1305ModifiedOutputAndSpeed(t *testing.T) {
	var key [32]byte
	var msg [1024]byte
	_, _ = rand.Read(key[:])
	_, _ = rand.Read(msg[:])

	var outOrig, outMod [16]byte

	// Check output difference
	poly1305.Sum(&outOrig, msg[:], &key)
	SumModified(&outMod, msg[:], &key)

	fmt.Printf("Original Poly1305: %x\n", outOrig)
	fmt.Printf("Modified Poly1305: %x\n", outMod)
	fmt.Printf("Diff (first byte): %d\n", int(outMod[0])-int(outOrig[0]))

	// Time original
	iters := 100000
	start := time.Now()
	for i := 0; i < iters; i++ {
		poly1305.Sum(&outOrig, msg[:], &key)
	}
	elapsedOrig := time.Since(start)

	// Time modified
	start = time.Now()
	for i := 0; i < iters; i++ {
		SumModified(&outMod, msg[:], &key)
	}
	elapsedMod := time.Since(start)

	fmt.Printf("Original Poly1305 time: %v for %d iterations\n", elapsedOrig, iters)
	fmt.Printf("Modified Poly1305 time: %v for %d iterations\n", elapsedMod, iters)
}

func TestPoly1795OutputAndSpeed(t *testing.T) {
	var key [32]byte
	var msg [1024]byte
	_, _ = rand.Read(key[:])
	_, _ = rand.Read(msg[:])

	var out1795 [24]byte

	// Output
	Poly1795Sum(&out1795, msg[:], &key)
	fmt.Printf("Poly1795 Output: %x\n", out1795)

	// Time Poly1795
	iters := 100000
	start := time.Now()
	for i := 0; i < iters; i++ {
		Poly1795Sum(&out1795, msg[:], &key)
	}
	elapsed1795 := time.Since(start)

	fmt.Printf("Poly1795 time: %v for %d iterations\n", elapsed1795, iters)
}

func TestDoublePoly1305OutputAndSpeed(t *testing.T) {
	var key [64]byte
	var msg [1024]byte
	_, _ = rand.Read(key[:])
	_, _ = rand.Read(msg[:])

	var outDouble [32]byte

	// Output
	DoublePoly1305(&outDouble, msg[:], &key)
	fmt.Printf("DoublePoly1305 Output: %x\n", outDouble)
	if len(outDouble) != 32 {
		t.Fatalf("DoublePoly1305 output length is not 32 bytes")
	}

	// Change message and check difference
	msg2 := make([]byte, len(msg))
	copy(msg2, msg[:])
	msg2[0] ^= 0xFF
	var outDouble2 [32]byte
	DoublePoly1305(&outDouble2, msg2, &key)
	if string(outDouble[:]) == string(outDouble2[:]) {
		t.Fatalf("DoublePoly1305 should differ for different messages")
	}

	// Time DoublePoly1305
	iters := 100000
	start := time.Now()
	for i := 0; i < iters; i++ {
		DoublePoly1305(&outDouble, msg[:], &key)
	}
	elapsedDouble := time.Since(start)

	fmt.Printf("DoublePoly1305 time: %v for %d iterations\n", elapsedDouble, iters)
} 