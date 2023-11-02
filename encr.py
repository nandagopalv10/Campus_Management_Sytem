from Crypto.Cipher import DES, DES3
import binascii

# Define the ciphertexts obtained earlier
ecb_ciphertext = "d03b7dd7f8d823e77e7e6a2b33ca5ca0"
cbc_ciphertext = "6a0c9db13dd01628d9d4d1490f12937a"

# Define the 64-bit DES key (should be the same as used for encryption)
key = b"12345678"  # Replace with your own key

# Create a DES object in ECB mode
ecb_cipher = DES.new(key, DES.MODE_ECB)

# Decrypt in ECB mode
ecb_decrypted = ecb_cipher.decrypt(binascii.unhexlify(ecb_ciphertext))
ecb_decrypted = ecb_decrypted.rstrip(b'\x01')  # Remove PKCS7 padding
ecb_decrypted = ecb_decrypted.decode('utf-8')  # Convert to string

iv = b"87654321"  # Replace with your own IV

cbc_cipher = DES3.new(key, DES3.MODE_CBC, iv)

# Decrypt in CBC mode
cbc_decrypted = cbc_cipher.decrypt(binascii.unhexlify(cbc_ciphertext))
cbc_decrypted = cbc_decrypted.rstrip(b'\x01')  # Remove PKCS7 padding
cbc_decrypted = cbc_decrypted.decode('utf-8')  # Convert to string

print("ECB Decrypted Plaintext:", ecb_decrypted)
print("CBC Decrypted Plaintext:", cbc_decrypted)
