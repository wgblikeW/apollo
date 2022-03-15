package utils

import (
	"errors"
)

func Padding(data []byte, blocksize int) ([]byte, error) {
	if len(data) > blocksize {
		return []byte{}, errors.New("data len is larger than target padding len")
	}
	padding_data := data
	for i := len(data); i < blocksize; i++ {
		padding_data = append(padding_data, byte(255))
	}
	return padding_data, nil
}

func Unpadding(data []byte) []byte {
	for i, b := range data {
		if b == byte(255) {
			return data[:i]
		}
	}
	return nil
}
