package encrypt64

// All 28147 operations are going with two 32-bit halves of the whole
// block. nv is representation of that one half.
type nv uint32

// Cyclic 11-bit shift.
func (n nv) shift11() nv {
	return ((n << 11) & (1<<32 - 1)) | ((n >> (32 - 11)) & (1<<32 - 1))
}

// Seq contains iteration numbers used in the encryption function
// itself. For example 28147 encryption and decryption process differs
// only with this sequence.
type Seq []uint8

var (
	SeqEncrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
	SeqDecrypt = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
	})
)

type Cipher struct {
	key  [KeySize]byte
	sbox *Sbox
	x    [8]nv
}

func NewCipher(key []byte, sbox *Sbox) *Cipher {
	if len(key) != KeySize {
		panic("invalid key size")
	}
	c := Cipher{sbox: sbox}
	copy(c.key[:], key)
	c.x = [8]nv{
		nv(key[0]) | nv(key[1])<<8 | nv(key[2])<<16 | nv(key[3])<<24,
		nv(key[4]) | nv(key[5])<<8 | nv(key[6])<<16 | nv(key[7])<<24,
		nv(key[8]) | nv(key[9])<<8 | nv(key[10])<<16 | nv(key[11])<<24,
		nv(key[12]) | nv(key[13])<<8 | nv(key[14])<<16 | nv(key[15])<<24,
		nv(key[16]) | nv(key[17])<<8 | nv(key[18])<<16 | nv(key[19])<<24,
		nv(key[20]) | nv(key[21])<<8 | nv(key[22])<<16 | nv(key[23])<<24,
		nv(key[24]) | nv(key[25])<<8 | nv(key[26])<<16 | nv(key[27])<<24,
		nv(key[28]) | nv(key[29])<<8 | nv(key[30])<<16 | nv(key[31])<<24,
	}
	return &c
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

// Convert binary byte block to two 32-bit internal integers.
func block2nvs(b []byte) (n1, n2 nv) {
	n1 = nv(b[0]) | nv(b[1])<<8 | nv(b[2])<<16 | nv(b[3])<<24
	n2 = nv(b[4]) | nv(b[5])<<8 | nv(b[6])<<16 | nv(b[7])<<24
	return
}

// Convert two 32-bit internal integers to binary byte block.
func nvs2block(n1, n2 nv, b []byte) {
	b[0] = byte((n2 >> 0) & 255)
	b[1] = byte((n2 >> 8) & 255)
	b[2] = byte((n2 >> 16) & 255)
	b[3] = byte((n2 >> 24) & 255)
	b[4] = byte((n1 >> 0) & 255)
	b[5] = byte((n1 >> 8) & 255)
	b[6] = byte((n1 >> 16) & 255)
	b[7] = byte((n1 >> 24) & 255)
}

func (c *Cipher) xcrypt(seq Seq, n1, n2 nv) (nv, nv) {
	for _, i := range seq {
		n1, n2 = c.sbox.k(n1+c.x[i]).shift11()^n2, n1
	}
	return n1, n2
}

func (c *Cipher) Encrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	n1, n2 = c.xcrypt(SeqEncrypt, n1, n2)
	nvs2block(n1, n2, dst)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	n1, n2 := block2nvs(src)
	n1, n2 = c.xcrypt(SeqDecrypt, n1, n2)
	nvs2block(n1, n2, dst)
}

// Sbox is a representation of eight substitution boxes.
type Sbox [8][16]uint8

var (
	SboxIdtc26gost28147paramZ = Sbox([8][16]uint8{
		{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
		{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
		{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
		{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
		{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
		{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
		{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
		{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
	})
)

// Sbox substitution itself.
func (s *Sbox) k(n nv) nv {
	return nv(s[0][(n>>0)&0x0F])<<0 +
		nv(s[1][(n>>4)&0x0F])<<4 +
		nv(s[2][(n>>8)&0x0F])<<8 +
		nv(s[3][(n>>12)&0x0F])<<12 +
		nv(s[4][(n>>16)&0x0F])<<16 +
		nv(s[5][(n>>20)&0x0F])<<20 +
		nv(s[6][(n>>24)&0x0F])<<24 +
		nv(s[7][(n>>28)&0x0F])<<28
}
