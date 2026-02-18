
import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class DocumentEncryption:
    """
    Handles AES-256-GCM encryption and decryption of documents.
    """

    def __init__(self):
        # In a real app, this should be loaded from a secure vault or env
        # For this project, we use a hardcoded master key if env is missing.
        self.master_key = os.environ.get('DOCUMENT_MASTER_KEY', 'CHANGE_THIS_TO_A_SECURE_RANDOM_KEY_IN_PRODUCTION')
        
        # Ensure master key is 32 bytes (256 bits)
        self.key_bytes = hashlib.sha256(self.master_key.encode()).digest()

    def encrypt_data(self, data: bytes):
        """
        Encrypts bytes using AES-GCM.
        Returns: { 'ciphertext': bytes, 'iv': bytes, 'tag': bytes, 'key': bytes }
        """
        # 1. Generate a unique key for this document (DEK - Data Encryption Key)
        dek = get_random_bytes(32) # 256-bit key
        
        # 2. Initialize Cipher
        cipher = AES.new(dek, AES.MODE_GCM)
        
        # 3. Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return {
            'ciphertext': ciphertext,
            'iv': cipher.nonce,
            'tag': tag,
            'key': dek
        }

    def decrypt_data(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes = None) -> bytes:
        """
        Decrypts AES-GCM encrypted data.
        """
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            if tag:
                return cipher.decrypt_and_verify(ciphertext, tag)
            else:
                return cipher.decrypt(ciphertext)
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise ValueError("Decryption failed. Data may be corrupted or key is incorrect.")

    def encrypt_file(self, file_path_in, file_path_out):
        """
        Encrypts a file and writes to disk.
        Returns base64 encoded 'key' and 'iv' for DB storage.
        """
        try:
            with open(file_path_in, 'rb') as f:
                data = f.read()
            
            result = self.encrypt_data(data)
            
            # Write ciphertext + tag to disk
            with open(file_path_out, 'wb') as f:
                f.write(result['ciphertext'])
                f.write(result['tag']) # Append 16-byte tag to file content
                
            return {
                'key': base64.b64encode(result['key']).decode('utf-8'),
                'iv': base64.b64encode(result['iv']).decode('utf-8')
            }
        except Exception as e:
            print(f"File encryption error: {e}")
            raise

    def decrypt_file(self, file_path_in, key_b64, iv_b64):
        """
        Reads encrypted file from disk, decrypts, and returns raw bytes.
        """
        try:
            if not os.path.exists(file_path_in):
                 raise FileNotFoundError(f"Encrypted file not found: {file_path_in}")

            with open(file_path_in, 'rb') as f:
                file_content = f.read()
                
            # Extract Tag (last 16 bytes)
            tag = file_content[-16:]
            ciphertext = file_content[:-16]
            
            key = base64.b64decode(key_b64)
            iv = base64.b64decode(iv_b64)
            
            return self.decrypt_data(ciphertext, key, iv, tag)
        except Exception as e:
             print(f"File decryption error: {e}")
             raise
