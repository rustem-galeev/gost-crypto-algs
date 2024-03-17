package encrypt128

import (
	"crypto/cipher"
	"fmt"
	"github.com/rustem-galeev/gost-crypto-algs/common"
)

const (
	BlockSize = 16 //128 bits
	KeySize   = 32 //256 bits
)

var (
	lc = [BlockSize]byte{
		148, 32, 133, 16,
		194, 192, 1, 251,
		1, 192, 194, 16,
		133, 32, 148, 1,
	}

	pi = []byte{
		252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
		233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
		249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
		5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
		235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
		181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
		21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
		50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
		223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
		224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
		167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
		173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
		7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
		225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
		32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
		89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
	}
	piInv [256]byte

	cBlk    [32][]byte
	gfCache [256][256]byte
)

func init() {
	for i := 0; i < 256; i++ {
		piInv[int(pi[i])] = byte(i)
	}

	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			gfCache[a][b] = gf(byte(a), byte(b))
		}
	}

	for i := 0; i < 32; i++ {
		cBlk[i] = make([]byte, BlockSize)
		cBlk[i][15] = byte(i) + 1
		l(cBlk[i])
	}
}

func gf(a, b byte) (c byte) {
	for b > 0 {
		if b&1 > 0 {
			c ^= a
		}
		if a&0x80 > 0 {
			a = (a << 1) ^ 0xC3
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return
}

type Gost3412Block128 struct {
	iterKeys [10][]byte
}

func New(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size")
	}

	iterKeys := buildIterKeys(key)

	return &Gost3412Block128{iterKeys: iterKeys}, nil
}

func (c *Gost3412Block128) BlockSize() int {
	return BlockSize
}

func (c *Gost3412Block128) Encrypt(dst, src []byte) {
	blk := make([]byte, BlockSize)
	copy(blk, src)

	for i := 0; i < 9; i++ {
		common.Xor(blk, blk, c.iterKeys[i])
		blk = s(blk)
		l(blk)
	}
	common.Xor(blk, blk, c.iterKeys[9])
	copy(dst[:BlockSize], blk)
}

func (c *Gost3412Block128) Decrypt(dst, src []byte) {
	blk := make([]byte, BlockSize)
	copy(blk, src)

	var n int
	for i := 9; i > 0; i-- {
		common.Xor(blk, blk, c.iterKeys[i])
		lInv(blk)
		for n = 0; n < BlockSize; n++ {
			blk[n] = piInv[int(blk[n])]
		}
	}
	common.Xor(blk, blk, c.iterKeys[0])
	copy(dst[:BlockSize], blk)
}

func l(blk []byte) {
	for n := 0; n < BlockSize; n++ {
		t := blk[15]
		for i := 0; i < BlockSize-1; i++ {
			t ^= gfCache[blk[i]][lc[i]]
		}
		copy(blk[1:], blk)
		blk[0] = t
	}
}

func lInv(blk []byte) {
	for n := 0; n < BlockSize; n++ {
		t := blk[0]
		copy(blk, blk[1:])
		for i := 0; i < BlockSize-1; i++ {
			t ^= gfCache[blk[i]][lc[i]]
		}
		blk[15] = t
	}
}

func s(data []byte) []byte {
	array := make([]byte, BlockSize)
	common.Replace(array, data, pi)
	return array
}

func buildIterKeys(key []byte) [10][]byte {
	var iterKeys [10][]byte
	for i := 0; i < len(iterKeys); i++ {
		iterKeys[i] = make([]byte, BlockSize)
	}

	kr0 := make([]byte, BlockSize)
	copy(kr0, key[:BlockSize])
	copy(iterKeys[0], kr0)
	kr1 := make([]byte, BlockSize)
	copy(kr1, key[BlockSize:])
	copy(iterKeys[1], kr1)

	krt := make([]byte, BlockSize)
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			common.Xor(krt, kr0, cBlk[8*i+j])
			krt = s(krt)
			l(krt)
			common.Xor(krt, krt, kr1)
			copy(kr1, kr0)
			copy(kr0, krt)
		}
		copy(iterKeys[2+2*i], kr0)
		copy(iterKeys[2+2*i+1], kr1)
	}

	return iterKeys
}
