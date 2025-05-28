// Package device provides a custom ChaCha20 implementation with 24 rounds and a 16-byte nonce for experimentation.
package device

import (
	"encoding/binary"
	"fmt"
)

const (
	chachaRounds = 24
	chachaKeySize = 32
	chachaNonceSize = 16
)

// quarterRound is the ChaCha20 quarter round function.
func quarterRound(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = (x[d] << 10) | (x[d] >> (32 - 10))
	x[d] += 1

	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = (x[b] << 14) | (x[b] >> (32 - 14))

	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = (x[d] << 6) | (x[d] >> (32 - 6))

	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = (x[b] << 9) | (x[b] >> (32 - 9))
}

// chachaBlock24 produces a 64-byte keystream block using 24 rounds and a 16-byte nonce.
func chachaBlock24(key *[32]byte, nonce *[16]byte, counter uint32, out *[64]byte) {
	if len(nonce) != 16 {
		panic(fmt.Sprintf("nonce must be 16 bytes, got %d", len(nonce)))
	}
	fmt.Printf("DEBUG: nonce len: %d\n", len(nonce))
	var x [16]uint32
	// Constants
	x[0] = 0x61707865
	x[1] = 0x3320646e
	x[2] = 0x79622d32
	x[3] = 0x6b206574
	// Key
	for i := 0; i < 8; i++ {
		x[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	// 16-byte nonce (mapped to x[11] through x[14])
	for i := 0; i < 4; i++ {
		start := i * 4
		end := (i + 1) * 4
		if end > len(nonce) {
			panic(fmt.Sprintf("nonce slice out of bounds: start=%d end=%d len=%d", start, end, len(nonce)))
		}
		fmt.Printf("DEBUG: nonce[%d:%d] (len=%d)\n", start, end, len(nonce))
		x[11+i] = binary.LittleEndian.Uint32(nonce[start:end])
	}
	// Counter (mapped to x[15])
	x[15] = counter
	orig := x
	for i := 0; i < chachaRounds; i += 2 {
		// Column rounds
		quarterRound(&x, 0, 4, 8, 12)
		quarterRound(&x, 1, 5, 9, 13)
		quarterRound(&x, 2, 6, 10, 14)
		quarterRound(&x, 3, 7, 11, 15)
		// Diagonal rounds
		quarterRound(&x, 0, 5, 10, 15)
		quarterRound(&x, 1, 6, 11, 12)
		quarterRound(&x, 2, 7, 8, 13)
		quarterRound(&x, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		x[i] += orig[i]
		binary.LittleEndian.PutUint32(out[i*4:], x[i])
	}
}

// EncryptChaCha20_24 encrypts plaintext using ChaCha20 with 24 rounds and a 16-byte nonce.
func EncryptChaCha20_24(key *[32]byte, nonce *[16]byte, counter uint32, plaintext []byte) []byte {
	var block [64]byte
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 64 {
		chachaBlock24(key, nonce, counter, &block)
		blockSize := 64
		if len(plaintext)-i < 64 {
			blockSize = len(plaintext) - i
		}
		for j := 0; j < blockSize; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ block[j]
		}
		counter++
	}
	return ciphertext
} 