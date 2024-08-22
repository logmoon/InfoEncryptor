import os
import json
import uuid
from cryptography.fernet import Fernet
import shutil

class EncryptionManager:
    def __init__(self, user_folder, master_key):
        self.key_store_path = os.path.join(user_folder, "key_store.enc")
        self.master_key = master_key
        self.keys = self.load_keys()
        self.ENCRYPTED_FILE_EXTENSION = " (ENCRYPTED).enc"
        self.DECRYPTED_FOLDER_EXTENSION = " (DECRYPTED)"

    def encrypt_data_with_master_key(self, data: bytes) -> bytes:
        fernet = Fernet(self.master_key)
        return fernet.encrypt(data)

    def decrypt_data_with_master_key(self, encrypted_data: bytes) -> bytes:
        fernet = Fernet(self.master_key)
        return fernet.decrypt(encrypted_data)

    def load_keys(self):
        if not os.path.exists(self.key_store_path):
            return {}
        with open(self.key_store_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = self.decrypt_data_with_master_key(encrypted_data)
        return json.loads(decrypted_data.decode())

    def save_key(self, label, key, folder_path):
        self.keys[label] = {
            "key": key.decode(),
            "path": folder_path
        }
        encrypted_data = self.encrypt_data_with_master_key(json.dumps(self.keys).encode())
        with open(self.key_store_path, 'wb') as f:
            f.write(encrypted_data)

    def get_key(self, label):
        if label in self.keys:
            return self.keys[label]["key"].encode()
        else:
            new_key = Fernet.generate_key()
            self.save_key(label, new_key, "")  # Save the new key with an empty folder path initially
            return new_key

    def update_folder_path(self, label, new_path):
        if label in self.keys:
            self.keys[label]["path"] = new_path
            self.save_keys()

    def save_keys(self):
        encrypted_data = self.encrypt_data_with_master_key(json.dumps(self.keys).encode())
        with open(self.key_store_path, 'wb') as f:
            f.write(encrypted_data)

    def get_all_encrypted_folders(self):
        return [(label, self.keys[label]["path"]) for label in self.keys]

    def generate_uuid(self):
        return str(uuid.uuid4())

    def encrypt_data(self, data: bytes, key: bytes, file_uuid: str) -> bytes:
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        return file_uuid.encode() + b'\n' + encrypted_data

    def decrypt_data(self, data: bytes, key: bytes) -> bytes:
        if b'\n' in data:
            file_uuid, encrypted_data = data.split(b'\n', 1)
        else:
            encrypted_data = data
        
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)

    def encrypt_file(self, file_path: str, output_file: str):
        file_uuid = self.generate_uuid()
        key = self.get_key(file_uuid)

        with open(file_path, 'rb') as file:
            file_data = file.read()

        encrypted_data = self.encrypt_data(file_data, key, file_uuid)

        with open(output_file, 'wb') as file:
            file.write(encrypted_data)

        self.save_key(file_uuid, key, output_file)

    def decrypt_file(self, encrypted_file: str, output_file: str):
        with open(encrypted_file, 'rb') as file:
            data = file.read()

        key = self.get_key(data.split(b'\n', 1)[0].decode() if b'\n' in data else encrypted_file)
        decrypted_data = self.decrypt_data(data, key)

        with open(output_file, 'wb') as file:
            file.write(decrypted_data)

    def compress_folder(self, folder_path: str, output_archive: str):
        shutil.make_archive(output_archive, 'gztar', folder_path)

    def decompress_folder(self, archive_file: str, output_folder: str):
        shutil.unpack_archive(archive_file, output_folder)