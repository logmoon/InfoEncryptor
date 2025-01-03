import os
import tarfile
import io
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

class EncryptionManager:
    def __init__(self):
        """Initialize encryption manager with a new encryption key"""
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def compress_folder(self, folder_path: str, output_path: str = None) -> bytes:
        """Compress a folder into a tar.gz archive in memory"""
        memory_file = io.BytesIO()
        
        with tarfile.open(fileobj=memory_file, mode='w:gz') as tar:
            # Add folder contents to tar
            tar.add(folder_path, arcname=os.path.basename(folder_path))
            
        # If output_path is provided, save to disk
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(memory_file.getvalue())
        
        return memory_file.getvalue()

    def extract_folder(self, archive_data: bytes, output_path: str):
        """Extract a tar.gz archive from bytes to a folder"""
        memory_file = io.BytesIO(archive_data)
        
        with tarfile.open(fileobj=memory_file, mode='r:gz') as tar:
            # Extract all contents
            tar.extractall(path=output_path)

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt bytes data"""
        return self.cipher_suite.encrypt(data)

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt bytes data"""
        return self.cipher_suite.decrypt(encrypted_data)

    def get_encryption_key(self) -> bytes:
        """Get the current encryption key"""
        return self.key