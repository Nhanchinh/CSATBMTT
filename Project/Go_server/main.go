package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Constants for AES
const Nb = 4 // Number of columns in state (fixed at 4 for AES)

// Substitution box (S-box)
var sBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// Inverse Substitution box (inverse S-box)
var invSBox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Round constant used for key expansion
var rCon = [11][4]byte{
	{0x00, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x00, 0x00},
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1b, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00},
}

// Determine Nk and Nr based on key length
func getNkNr(keyLength int) (int, int, error) {
	switch keyLength {
	case 16:
		return 4, 10, nil // AES-128
	case 24:
		return 6, 12, nil // AES-192
	case 32:
		return 8, 14, nil // AES-256
	default:
		return 0, 0, errors.New("unsupported key length. Use 16, 24, or 32 bytes")
	}
}

// AES SubBytes - Substitute bytes using S-box
func subBytes(state [4][Nb]byte) [4][Nb]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			state[i][j] = sBox[state[i][j]]
		}
	}
	return state
}

// AES InvSubBytes - Substitute bytes using inverse S-box
func invSubBytes(state [4][Nb]byte) [4][Nb]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			state[i][j] = invSBox[state[i][j]]
		}
	}
	return state
}

// AES ShiftRows - Shift rows of state array
func shiftRows(state [4][Nb]byte) [4][Nb]byte {
	var temp byte

	temp = state[1][0]
	state[1][0] = state[1][1]
	state[1][1] = state[1][2]
	state[1][2] = state[1][3]
	state[1][3] = temp

	temp = state[2][0]
	state[2][0] = state[2][2]
	state[2][2] = temp
	temp = state[2][1]
	state[2][1] = state[2][3]
	state[2][3] = temp

	temp = state[3][3]
	state[3][3] = state[3][2]
	state[3][2] = state[3][1]
	state[3][1] = state[3][0]
	state[3][0] = temp

	return state
}

// AES InvShiftRows - Inverse shift rows of state array
func invShiftRows(state [4][Nb]byte) [4][Nb]byte {
	var temp byte

	temp = state[1][3]
	state[1][3] = state[1][2]
	state[1][2] = state[1][1]
	state[1][1] = state[1][0]
	state[1][0] = temp

	temp = state[2][0]
	state[2][0] = state[2][2]
	state[2][2] = temp
	temp = state[2][1]
	state[2][1] = state[2][3]
	state[2][3] = temp

	temp = state[3][0]
	state[3][0] = state[3][1]
	state[3][1] = state[3][2]
	state[3][2] = state[3][3]
	state[3][3] = temp

	return state
}

// Galois field multiplication (GF(2^8))
func galoisMult(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		hiBitSet := (a & 0x80) != 0
		a <<= 1
		if hiBitSet {
			a ^= 0x1b // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

// AES MixColumns - Mix columns of state array
func mixColumns(state [4][Nb]byte) [4][Nb]byte {
	temp := [4]byte{}
	for j := 0; j < Nb; j++ {
		for i := 0; i < 4; i++ {
			temp[i] = state[i][j]
		}
		state[0][j] = galoisMult(temp[0], 2) ^ galoisMult(temp[1], 3) ^ temp[2] ^ temp[3]
		state[1][j] = temp[0] ^ galoisMult(temp[1], 2) ^ galoisMult(temp[2], 3) ^ temp[3]
		state[2][j] = temp[0] ^ temp[1] ^ galoisMult(temp[2], 2) ^ galoisMult(temp[3], 3)
		state[3][j] = galoisMult(temp[0], 3) ^ temp[1] ^ temp[2] ^ galoisMult(temp[3], 2)
	}
	return state
}

// AES InvMixColumns - Inverse mix columns of state array
func invMixColumns(state [4][Nb]byte) [4][Nb]byte {
	temp := [4]byte{}
	for j := 0; j < Nb; j++ {
		for i := 0; i < 4; i++ {
			temp[i] = state[i][j]
		}
		state[0][j] = galoisMult(temp[0], 0x0e) ^ galoisMult(temp[1], 0x0b) ^ galoisMult(temp[2], 0x0d) ^ galoisMult(temp[3], 0x09)
		state[1][j] = galoisMult(temp[0], 0x09) ^ galoisMult(temp[1], 0x0e) ^ galoisMult(temp[2], 0x0b) ^ galoisMult(temp[3], 0x0d)
		state[2][j] = galoisMult(temp[0], 0x0d) ^ galoisMult(temp[1], 0x09) ^ galoisMult(temp[2], 0x0e) ^ galoisMult(temp[3], 0x0b)
		state[3][j] = galoisMult(temp[0], 0x0b) ^ galoisMult(temp[1], 0x0d) ^ galoisMult(temp[2], 0x09) ^ galoisMult(temp[3], 0x0e)
	}
	return state
}

// AES AddRoundKey - XOR state with round key
func addRoundKey(state [4][Nb]byte, roundKey [][4]byte, round int) [4][Nb]byte {
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			state[i][j] ^= roundKey[round*Nb+j][i]
		}
	}
	return state
}

// Rotate word (used in key expansion)
func rotWord(word [4]byte) [4]byte {
	temp := word[0]
	for i := 0; i < 3; i++ {
		word[i] = word[i+1]
	}
	word[3] = temp
	return word
}

// Apply S-box to each byte in word (used in key expansion)
func subWord(word [4]byte) [4]byte {
	for i := 0; i < 4; i++ {
		word[i] = sBox[word[i]]
	}
	return word
}

// Key Expansion - Expand the key into the key schedule
func keyExpansion(key []byte) ([][4]byte, int) {
	Nk, Nr, err := getNkNr(len(key))
	if err != nil {
		panic(err)
	}

	w := make([][4]byte, Nb*(Nr+1))
	var temp [4]byte

	i := 0
	for i < Nk {
		w[i] = [4]byte{key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]}
		i++
	}

	for i = Nk; i < Nb*(Nr+1); i++ {
		temp = w[i-1]
		if i%Nk == 0 {
			temp = subWord(rotWord(temp))
			for j := 0; j < 4; j++ {
				temp[j] ^= rCon[i/Nk][j]
			}
		} else if Nk > 6 && i%Nk == 4 {
			temp = subWord(temp)
		}
		w[i] = [4]byte{}
		for j := 0; j < 4; j++ {
			w[i][j] = w[i-Nk][j] ^ temp[j]
		}
	}

	return w, Nr
}

// Pad data to a multiple of 16 bytes (AES block size)
func padData(data []byte) []byte {
	blockSize := 16
	padLength := blockSize - (len(data) % blockSize)
	paddedData := make([]byte, len(data)+padLength)
	copy(paddedData, data)
	for i := len(data); i < len(paddedData); i++ {
		paddedData[i] = byte(padLength) // PKCS#7 padding
	}
	return paddedData
}

// Remove padding from data
func unpadData(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errors.New("invalid decrypted data length")
	}
	padLength := int(data[len(data)-1])
	if padLength < 1 || padLength > 16 {
		return nil, errors.New("invalid padding length")
	}
	for i := len(data) - padLength; i < len(data); i++ {
		if data[i] != byte(padLength) {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return data[:len(data)-padLength], nil
}

// AES Encryption - Encrypt a 16-byte block
func encryptBlock(input []byte, w [][4]byte, Nr int) [16]byte {
	var state [4][Nb]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			state[i][j] = input[i+4*j]
		}
	}

	state = addRoundKey(state, w, 0)
	for round := 1; round < Nr; round++ {
		state = subBytes(state)
		state = shiftRows(state)
		state = mixColumns(state)
		state = addRoundKey(state, w, round)
	}
	state = subBytes(state)
	state = shiftRows(state)
	state = addRoundKey(state, w, Nr)

	var output [16]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			output[i+4*j] = state[i][j]
		}
	}
	return output
}

// AES Decryption - Decrypt a 16-byte block
func decryptBlock(input []byte, w [][4]byte, Nr int) [16]byte {
	var state [4][Nb]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			state[i][j] = input[i+4*j]
		}
	}

	state = addRoundKey(state, w, Nr)
	for round := Nr - 1; round > 0; round-- {
		state = invShiftRows(state)
		state = invSubBytes(state)
		state = addRoundKey(state, w, round)
		state = invMixColumns(state)
	}
	state = invShiftRows(state)
	state = invSubBytes(state)
	state = addRoundKey(state, w, 0)

	var output [16]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < Nb; j++ {
			output[i+4*j] = state[i][j]
		}
	}
	return output
}

// Encrypt the input data using AES
func Encrypt(input string, key string) (string, error) {
	keyBytes := []byte(key)
	if !contains([]int{16, 24, 32}, len(keyBytes)) {
		return "", fmt.Errorf("key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256, got %d", len(keyBytes))
	}

	inputBytes := padData([]byte(input))
	w, Nr := keyExpansion(keyBytes)
	output := make([]byte, len(inputBytes))

	for i := 0; i < len(inputBytes); i += 16 {
		block := inputBytes[i : i+16]
		encryptedBlock := encryptBlock(block, w, Nr)
		copy(output[i:i+16], encryptedBlock[:])
	}

	return base64.StdEncoding.EncodeToString(output), nil
}

// Decrypt the encrypted data using AES
func Decrypt(input string, key string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %v", err)
	}

	keyBytes := []byte(key)
	if !contains([]int{16, 24, 32}, len(keyBytes)) {
		return "", fmt.Errorf("key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256, got %d", len(keyBytes))
	}

	if len(encryptedBytes)%16 != 0 {
		return "", errors.New("invalid encrypted data length")
	}

	w, Nr := keyExpansion(keyBytes)
	output := make([]byte, len(encryptedBytes))

	for i := 0; i < len(encryptedBytes); i += 16 {
		block := encryptedBytes[i : i+16]
		decryptedBlock := decryptBlock(block, w, Nr)
		copy(output[i:i+16], decryptedBlock[:])
	}

	unpadded, err := unpadData(output)
	if err != nil {
		return "", fmt.Errorf("unpad error: %v", err)
	}
	return string(unpadded), nil
}

// Helper function to check if a slice contains a value
func contains(slice []int, value int) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// EncryptRequest represents the structure for encryption requests
type EncryptRequest struct {
	Plaintext string `json:"plaintext" binding:"required"`
	Key       string `json:"key" binding:"required"`
}

// DecryptRequest represents the structure for decryption requests
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext" binding:"required"`
	Key        string `json:"key" binding:"required"`
}

// EncryptResponse represents the response for encryption
type EncryptResponse struct {
	Ciphertext   string  `json:"ciphertext"`
	KeyLength    int     `json:"key_length"`
	EncryptTime  float64 `json:"encrypt_time_ms"`
}

// DecryptResponse represents the response for decryption
type DecryptResponse struct {
	Plaintext   string  `json:"plaintext"`
	KeyLength   int     `json:"key_length"`
	DecryptTime float64 `json:"decrypt_time_ms"`
}

// ErrorResponse represents error responses
type ErrorResponse struct {
	Error string `json:"error"`
}

// Decrypt handler for the decryption endpoint
func decryptHandler(c *gin.Context) {
	var req DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate key length
	if !contains([]int{16, 24, 32}, len(req.Key)) {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("key length must be 16, 24, or 32 bytes, got %d", len(req.Key)),
		})
		return
	}

	// Measure decryption time with nanosecond precision
	startTime := time.Now()
	decrypted, err := Decrypt(req.Ciphertext, req.Key)
	
	// Calculate duration in milliseconds with nanosecond precision
	decryptDuration := float64(time.Since(startTime).Nanoseconds()) / 1_000_000 

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, DecryptResponse{
		Plaintext:   decrypted,
		KeyLength:   len(req.Key),
		DecryptTime: decryptDuration,
	})
}

// Tương tự với encryptHandler
func encryptHandler(c *gin.Context) {
	var req EncryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate key length
	if !contains([]int{16, 24, 32}, len(req.Key)) {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("key length must be 16, 24, or 32 bytes, got %d", len(req.Key)),
		})
		return
	}

	// Measure encryption time with nanosecond precision
	startTime := time.Now()
	encrypted, err := Encrypt(req.Plaintext, req.Key)
	
	// Calculate duration in milliseconds with nanosecond precision
	encryptDuration := float64(time.Since(startTime).Nanoseconds()) / 1_000_000 

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, EncryptResponse{
		Ciphertext:   encrypted,
		KeyLength:    len(req.Key),
		EncryptTime:  encryptDuration,
	})
}

// setupRouter configures the Gin router
func setupRouter() *gin.Engine {
	r := gin.Default()

	// Enable CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Encryption endpoint
	r.POST("/encrypt", encryptHandler)

	// Decryption endpoint
	r.POST("/decrypt", decryptHandler)

	return r
}

// Main function to start the server
func main() {
	router := setupRouter()
	
	// Start server on port 8080
	fmt.Println("Server starting on :8080")
	router.Run(":8080")
}