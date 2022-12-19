package auth

// Encrypt will encrypt a raw string to
// an encrypted value
// an encrypted value has an IV (nonce) + actual encrypted value
// when we decrypt, we only decrypt the latter part
func Encrypt(key []byte) ([]byte, error) {
	secretKey := FindSecret()

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(iv, iv, key, nil)

	return ciphertext, nil
}



// Decrypt will return the original value of the encrypted string
func Decrypt(encryptedKey []byte) ([]byte, error) {
	secretKey := FindSecret()

	block, err := aes.NewCipher(secretKey)

	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(encryptedKey) < aesgcm.NonceSize() {
		// worth panicking when encrypted key is bad
		panic("Malformed encrypted key")
	}

	return aesgcm.Open(
		nil,
		encryptedKey[:aesgcm.NonceSize()],
		encryptedKey[aesgcm.NonceSize():],
		nil,
	)
}



func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
