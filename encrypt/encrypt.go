package encrypt

import "crypto/cipher"

type Encrypt struct {
}

func New() cipher.Block {
	return new(Encrypt)
}

func (e Encrypt) BlockSize() int {
	print("BlockSize")
	return 1
}

func (e Encrypt) Encrypt(dst, src []byte) {
	print("Encrypt")
}

func (e Encrypt) Decrypt(dst, src []byte) {
	print("Decrypt")
}
