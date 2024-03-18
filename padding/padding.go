package padding

// процедура 2

func AddPadding(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	padding := make([]byte, paddingSize)
	padding[0] = byte(0x80) //10000000
	return append(data, padding...)
}

func RemovePadding(data []byte) []byte {
	var paddingBeginIndex int
	for i := len(data) - 1; true; i-- {
		if data[i] == 0x80 {
			paddingBeginIndex = i
			break
		}
	}
	return data[:paddingBeginIndex]
}
