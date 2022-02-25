from Crypto.Cipher import AES
import scrypt
import os
# https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples


class AESEncryptorDecryptor(object):
    def __init__(self, seed=16):
        self.seed = seed

    def encrypt_decrypt(self, password, action, msg=None, encrypted_msg=None):
        if action == 'encrypt':
            if msg is not None:
                return self.encrypt_aes_gcm(msg, password)
        elif action == 'decrypt':
            if encrypted_msg is not None:
                return self.decrypt_aes_gcm(encrypted_msg, password)

    def encrypt_aes_gcm(self, msg, password):
        msg = msg.encode('utf-8')
        kdf_salt = os.urandom(self.seed)
        secret_key = scrypt.hash(password, kdf_salt, N=16384, r=8, p=1, buflen=32)
        aes_cipher = AES.new(secret_key, AES.MODE_GCM)
        ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
        return kdf_salt, ciphertext, aes_cipher.nonce, auth_tag

    @staticmethod
    def decrypt_aes_gcm(encrypted_msg, password):
        kdf_salt, ciphertext, nonce, auth_tag = encrypted_msg
        secret_key = scrypt.hash(password, kdf_salt, N=16384, r=8, p=1, buflen=32)
        aes_cipher = AES.new(secret_key, AES.MODE_GCM, nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext
