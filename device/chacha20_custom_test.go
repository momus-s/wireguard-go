package device

import (
	"crypto/rand"
	"fmt"
	"testing"
	"golang.org/x/crypto/chacha20"
	"time"
)

func TestCustomChaCha20_24_vs_Standard(t *testing.T) {
	var key [32]byte
	var nonce16 [16]byte
	var nonce12 [12]byte
	var plaintext [1024]byte
	_, _ = rand.Read(key[:])
	_, _ = rand.Read(nonce16[:])
	copy(nonce12[:], nonce16[:12])
	_, _ = rand.Read(plaintext[:])

	// Standard Go chacha20 (20 rounds, 12-byte nonce)
	stdCipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce12[:])
	if err != nil {
		t.Fatalf("Failed to create standard chacha20 cipher: %v", err)
	}
	stdOut := make([]byte, len(plaintext))
	stdCipher.SetCounter(0)
	stdCipher.XORKeyStream(stdOut, plaintext[:])

	iters := 10000
	startStd := time.Now()
	for i := 0; i < iters; i++ {
		stdCipher, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce12[:])
		stdCipher.SetCounter(0)
		stdCipher.XORKeyStream(stdOut, plaintext[:])
	}
	elapsedStd := time.Since(startStd)

	// Custom 24-round, 16-byte nonce
	customOut := EncryptChaCha20_24(&key, &nonce16, 0, plaintext[:])
	startCustom := time.Now()
	for i := 0; i < iters; i++ {
		_ = EncryptChaCha20_24(&key, &nonce16, 0, plaintext[:])
	}
	elapsedCustom := time.Since(startCustom)

	fmt.Printf("Standard ChaCha20 (20 rounds, 12-byte nonce) output: %x...\n", stdOut[:16])
	fmt.Printf("Custom ChaCha20 (24 rounds, 16-byte nonce) output: %x...\n", customOut[:16])
	fmt.Printf("Standard ChaCha20 time: %v for %d iterations\n", elapsedStd, iters)
	fmt.Printf("Custom ChaCha20_24 time: %v for %d iterations\n", elapsedCustom, iters)

	// Academic comparison: Ensure outputs are different
	if len(stdOut) != len(customOut) {
		t.Fatalf("Output lengths mismatch: standard %d, custom %d", len(stdOut), len(customOut))
	}
	if string(stdOut) == string(customOut) {
		t.Fatalf("Academically modified ChaCha20 output matches standard ChaCha20 output, which is unexpected.")
	}
}

func TestSimpleCustomChaCha20_24(t *testing.T) {
	key := [32]byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32}
	nonce := [16]byte{101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116}
	plaintext := []byte("hello world")

	ciphertext := EncryptChaCha20_24(&key, &nonce, 0, plaintext)
	decrypted := EncryptChaCha20_24(&key, &nonce, 0, ciphertext)

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text does not match original: got %q, want %q", decrypted, plaintext)
	}
} 