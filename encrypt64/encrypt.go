package encrypt64

import (
	"crypto/cipher"
	"fmt"
)

const (
	BlockSize = 8
	KeySize   = 32
)

type CipherU struct {
	c   *Cipher
	blk *[BlockSize]byte
}

func New(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size")
	}
	keyCompatible := make([]byte, KeySize)
	for i := 0; i < KeySize/4; i++ {
		keyCompatible[i*4+0] = key[i*4+3]
		keyCompatible[i*4+1] = key[i*4+2]
		keyCompatible[i*4+2] = key[i*4+1]
		keyCompatible[i*4+3] = key[i*4+0]
	}
	return &CipherU{
		c:   NewCipher(keyCompatible, &SboxIdtc26gost28147paramZ),
		blk: new([BlockSize]byte),
	}, nil
}

func (c *CipherU) BlockSize() int {
	return BlockSize
}

func (c *CipherU) Encrypt(dst, src []byte) {
	c.blk[0] = src[7]
	c.blk[1] = src[6]
	c.blk[2] = src[5]
	c.blk[3] = src[4]
	c.blk[4] = src[3]
	c.blk[5] = src[2]
	c.blk[6] = src[1]
	c.blk[7] = src[0]
	c.c.Encrypt(c.blk[:], c.blk[:])
	dst[0] = c.blk[7]
	dst[1] = c.blk[6]
	dst[2] = c.blk[5]
	dst[3] = c.blk[4]
	dst[4] = c.blk[3]
	dst[5] = c.blk[2]
	dst[6] = c.blk[1]
	dst[7] = c.blk[0]
}

func (c *CipherU) Decrypt(dst, src []byte) {
	c.blk[0] = src[7]
	c.blk[1] = src[6]
	c.blk[2] = src[5]
	c.blk[3] = src[4]
	c.blk[4] = src[3]
	c.blk[5] = src[2]
	c.blk[6] = src[1]
	c.blk[7] = src[0]
	c.c.Decrypt(c.blk[:], c.blk[:])
	dst[0] = c.blk[7]
	dst[1] = c.blk[6]
	dst[2] = c.blk[5]
	dst[3] = c.blk[4]
	dst[4] = c.blk[3]
	dst[5] = c.blk[2]
	dst[6] = c.blk[1]
	dst[7] = c.blk[0]
}
