package common

func Xor(dst, x, y []byte) []byte {
	for i := 0; i < len(dst); i++ {
		dst[i] = x[i] ^ y[i]
	}
	return dst
}

func Replace(dst, data, replaceTable []byte) []byte {
	for i := 0; i < len(dst); i++ {
		dst[i] = replaceTable[int(data[i])]
	}
	return dst
}
