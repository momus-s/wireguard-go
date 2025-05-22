// Package poly1305_modified is a copy of golang.org/x/crypto/poly1305 for modification and benchmarking.
// This is the original implementation, unmodified.
// Copyright (c) The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package device

import (
	"encoding/binary"
	"golang.org/x/crypto/poly1305"
)

const (
	TagSize = 16
)

// Experimental: Poly1795, a PolyMAC with 179-bit accumulator and modulus 2^179-5
// This is NOT standard Poly1305 and is for benchmarking/experimentation only.

type poly1795MAC struct {
	r [6]uint32
	h [6]uint32
	pad [4]uint32
	buffer [24]byte // 24 bytes = 192 bits
	bufUsed int
	finalized bool
}

func newPoly1795MAC(key *[32]byte) *poly1795MAC {
	var m poly1795MAC
	// Use 6 limbs of 29 bits each for r
	m.r[0] = binary.LittleEndian.Uint32(key[0:4]) & 0x1fffffff
	m.r[1] = (binary.LittleEndian.Uint32(key[3:7]) >> 3) & 0x1fffffff
	m.r[2] = (binary.LittleEndian.Uint32(key[6:10]) >> 6) & 0x1fffffff
	m.r[3] = (binary.LittleEndian.Uint32(key[9:13]) >> 9) & 0x1fffffff
	m.r[4] = (binary.LittleEndian.Uint32(key[12:16]) >> 12) & 0x1fffffff
	m.r[5] = (binary.LittleEndian.Uint32(key[15:19]) >> 15) & 0x1fffffff
	m.pad[0] = binary.LittleEndian.Uint32(key[20:24])
	m.pad[1] = binary.LittleEndian.Uint32(key[24:28])
	m.pad[2] = binary.LittleEndian.Uint32(key[28:32])
	m.pad[3] = binary.LittleEndian.Uint32(key[16:20])
	return &m
}

func (m *poly1795MAC) Write(p []byte) (n int, err error) {
	n = len(p)
	if m.finalized {
		panic("poly1795: Write after Sum or Verify")
	}
	if m.bufUsed > 0 {
		remaining := 24 - m.bufUsed
		if len(p) < remaining {
			copy(m.buffer[m.bufUsed:], p)
			m.bufUsed += len(p)
			return n, nil
		}
		copy(m.buffer[m.bufUsed:], p[:remaining])
		m.processBlock(m.buffer[:], false)
		p = p[remaining:]
		m.bufUsed = 0
	}
	for len(p) >= 24 {
		m.processBlock(p[:24], false)
		p = p[24:]
	}
	if len(p) > 0 {
		copy(m.buffer[:], p)
		m.bufUsed = len(p)
	}
	return n, nil
}

func (m *poly1795MAC) processBlock(block []byte, isFinal bool) {
	var t [6]uint32
	for i := 0; i < 6; i++ {
		if i*4 < len(block) {
			t[i] = binary.LittleEndian.Uint32(block[i*4:])
		} else {
			t[i] = 0
		}
	}
	if isFinal {
		t[m.bufUsed/4] |= 1 << ((m.bufUsed % 4) * 8)
	}
	for i := 0; i < 6; i++ {
		m.h[i] += t[i]
	}
	// (h * r) mod (2^179 - 5)
	hr := [6]uint64{}
	for i := 0; i < 6; i++ {
		for j := 0; j <= i; j++ {
			hr[i] += uint64(m.h[j]) * uint64(m.r[i-j])
		}
		for j := i + 1; j < 6; j++ {
			hr[i] += uint64(m.h[j]) * uint64(5*m.r[i+6-j])
		}
	}
	for i := 0; i < 6; i++ {
		m.h[i] = uint32(hr[i] & 0x1fffffff)
		if i < 5 {
			hr[i+1] += hr[i] >> 29
		}
	}
}

func (m *poly1795MAC) Sum(out []byte) []byte {
	if m.finalized {
		panic("poly1795: Sum after Sum or Verify")
	}
	if m.bufUsed > 0 {
		for i := m.bufUsed; i < 24; i++ {
			m.buffer[i] = 0
		}
		m.processBlock(m.buffer[:], true)
	}
	m.finalized = true
	var f [6]uint32
	var c uint32
	for i := 0; i < 6; i++ {
		f[i] = m.h[i]
	}
	for i := 1; i < 6; i++ {
		f[i] += f[i-1] >> 29
		f[i-1] &= 0x1fffffff
	}
	f[0] += 5 * (f[5] >> 29)
	f[5] &= 0x1fffffff
	// compute h + -p
	g := [6]uint32{}
	g[0] = f[0] + 5
	c = g[0] >> 29
	g[0] &= 0x1fffffff
	for i := 1; i < 6; i++ {
		g[i] = f[i] + c
		c = g[i] >> 29
		g[i] &= 0x1fffffff
	}
	mask := (c ^ 1) - 1
	for i := 0; i < 6; i++ {
		f[i] = (f[i] &^ mask) | (g[i] & mask)
	}
	// serialize (output 24 bytes)
	var tag [24]byte
	for i := 0; i < 6; i++ {
		binary.LittleEndian.PutUint32(tag[i*4:], f[i])
	}
	// add pad (first 16 bytes only, for compatibility)
	var t uint32
	for i := 0; i < 4; i++ {
		t = binary.LittleEndian.Uint32(tag[i*4:]) + m.pad[i]
		binary.LittleEndian.PutUint32(tag[i*4:], t)
	}
	return append(out, tag[:]...)
}

// Poly1795Sum computes the experimental 179-bit MAC
func Poly1795Sum(out *[24]byte, m []byte, key *[32]byte) {
	mac := newPoly1795MAC(key)
	mac.Write(m)
	result := mac.Sum(nil)
	copy(out[:], result)
}

// Restore the original Poly1305 copy with minimal modification for comparison
type poly1305MAC struct {
	r [5]uint32
	h [5]uint32
	pad [4]uint32
	buffer [16]byte
	bufUsed int
	finalized bool
}

func newPoly1305MAC(key *[32]byte) *poly1305MAC {
	var m poly1305MAC
	m.r[0] = binary.LittleEndian.Uint32(key[0:4]) & 0x3ffffff
	m.r[1] = (binary.LittleEndian.Uint32(key[3:7]) >> 2) & 0x3ffff03
	m.r[2] = (binary.LittleEndian.Uint32(key[6:10]) >> 4) & 0x3ffc0ff
	m.r[3] = (binary.LittleEndian.Uint32(key[9:13]) >> 6) & 0x3f03fff
	m.r[4] = (binary.LittleEndian.Uint32(key[12:16]) >> 8) & 0x00fffff
	m.pad[0] = binary.LittleEndian.Uint32(key[16:20])
	m.pad[1] = binary.LittleEndian.Uint32(key[20:24])
	m.pad[2] = binary.LittleEndian.Uint32(key[24:28])
	m.pad[3] = binary.LittleEndian.Uint32(key[28:32])
	return &m
}

func (m *poly1305MAC) Write(p []byte) (n int, err error) {
	n = len(p)
	if m.finalized {
		panic("poly1305: Write after Sum or Verify")
	}
	if m.bufUsed > 0 {
		remaining := 16 - m.bufUsed
		if len(p) < remaining {
			copy(m.buffer[m.bufUsed:], p)
			m.bufUsed += len(p)
			return n, nil
		}
		copy(m.buffer[m.bufUsed:], p[:remaining])
		m.processBlock(m.buffer[:], false)
		p = p[remaining:]
		m.bufUsed = 0
	}
	for len(p) >= 16 {
		m.processBlock(p[:16], false)
		p = p[16:]
	}
	if len(p) > 0 {
		copy(m.buffer[:], p)
		m.bufUsed = len(p)
	}
	return n, nil
}

func (m *poly1305MAC) processBlock(block []byte, isFinal bool) {
	var t [5]uint32
	for i := 0; i < 4; i++ {
		t[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	t[4] = 0
	if isFinal {
		t[m.bufUsed/4] |= 1 << ((m.bufUsed % 4) * 8)
	}
	for i := 0; i < 5; i++ {
		m.h[i] += t[i]
	}
	// (h * r) mod (2^130 - 5)
	hr := [5]uint64{}
	for i := 0; i < 5; i++ {
		for j := 0; j <= i; j++ {
			hr[i] += uint64(m.h[j]) * uint64(m.r[i-j])
		}
		for j := i + 1; j < 5; j++ {
			hr[i] += uint64(m.h[j]) * uint64(5*m.r[i+5-j])
		}
	}
	for i := 0; i < 5; i++ {
		m.h[i] = uint32(hr[i] & 0x3ffffff)
		if i < 4 {
			hr[i+1] += hr[i] >> 26
		}
	}
}

func (m *poly1305MAC) Sum(out []byte) []byte {
	if m.finalized {
		panic("poly1305: Sum after Sum or Verify")
	}
	if m.bufUsed > 0 {
		for i := m.bufUsed; i < 16; i++ {
			m.buffer[i] = 0
		}
		m.processBlock(m.buffer[:], true)
	}
	m.finalized = true
	var f [5]uint32
	var c uint32
	for i := 0; i < 5; i++ {
		f[i] = m.h[i]
	}
	f[1] += f[0] >> 26
	f[0] &= 0x3ffffff
	f[2] += f[1] >> 26
	f[1] &= 0x3ffffff
	f[3] += f[2] >> 26
	f[2] &= 0x3ffffff
	f[4] += f[3] >> 26
	f[3] &= 0x3ffffff
	f[0] += 5 * (f[4] >> 26)
	f[4] &= 0x3ffffff
	// compute h + -p
	g := [5]uint32{}
	g[0] = f[0] + 5
	c = g[0] >> 26
	g[0] &= 0x3ffffff
	for i := 1; i < 5; i++ {
		g[i] = f[i] + c
		c = g[i] >> 26
		g[i] &= 0x3ffffff
	}
	mask := (c ^ 1) - 1
	for i := 0; i < 5; i++ {
		f[i] = (f[i] &^ mask) | (g[i] & mask)
	}
	// serialize
	var tag [16]byte
	f[1] <<= 26
	f[2] <<= 20
	f[3] <<= 14
	f[4] <<= 8
	out32 := f[0] | f[1]
	binary.LittleEndian.PutUint32(tag[0:4], out32)
	out32 = (f[1] >> 6) | f[2]
	binary.LittleEndian.PutUint32(tag[4:8], out32)
	out32 = (f[2] >> 12) | f[3]
	binary.LittleEndian.PutUint32(tag[8:12], out32)
	out32 = (f[3] >> 18) | f[4]
	binary.LittleEndian.PutUint32(tag[12:16], out32)
	// add pad
	var t uint32
	for i := 0; i < 4; i++ {
		t = binary.LittleEndian.Uint32(tag[i*4:]) + m.pad[i]
		binary.LittleEndian.PutUint32(tag[i*4:], t)
	}
	return append(out, tag[:]...)
}

func SumModified(out *[16]byte, m []byte, key *[32]byte) {
	mac := newPoly1305MAC(key)
	mac.Write(m)
	result := mac.Sum(nil)
	// Minimal modification: increment the first byte of the tag by 1
	if len(result) > 0 {
		result[0] = byte(result[0] + 1)
	}
	copy(out[:], result)
}

// DoublePoly1305 computes two independent Poly1305 MACs and concatenates the results for a 32-byte tag.
func DoublePoly1305(out *[32]byte, m []byte, key *[64]byte) {
	var tag1, tag2 [16]byte
	poly1305.Sum(&tag1, m, (*[32]byte)(key[:32]))
	poly1305.Sum(&tag2, m, (*[32]byte)(key[32:]))
	copy(out[:16], tag1[:])
	copy(out[16:], tag2[:])
} 