import os
import json

class LoginManager:
    def __init__(self, user_folder, encryption_manager):
        self.encryption_manager = encryption_manager
        self.login_data_file = os.path.join(user_folder, "login_data.enc")
        self.file_uuid = None

    def load_login_data(self):
        if os.path.exists(self.login_data_file):
            with open(self.login_data_file, 'rb') as file:
                encrypted_data = file.read()

            self.file_uuid = self.extract_uuid(encrypted_data)
            key = self.encryption_manager.get_key(self.file_uuid)
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data, key)
            return json.loads(decrypted_data.decode())
        return []

    def save_login_data(self, data):
        # Ensure UUID is persistent across sessions
        if not self.file_uuid:
            self.file_uuid = self.encryption_manager.generate_uuid()
        
        key = self.encryption_manager.get_key(self.file_uuid)
        encrypted_data = self.encryption_manager.encrypt_data(json.dumps(data).encode(), key, self.file_uuid)
        with open(self.login_data_file, 'wb') as file:
            file.write(encrypted_data)

    def add_login_entry(self, email, password, website):
        data = self.load_login_data()
        data.append({"email": email, "password": password, "website": website})
        self.save_login_data(data)

    def delete_login_entry(self, index):
        data = self.load_login_data()
        del data[index]
        self.save_login_data(data)

    def extract_uuid(self, data: bytes) -> str:
        if b'\n' in data:
            file_uuid, _ = data.split(b'\n', 1)
            return file_uuid.decode()
        raise ValueError("UUID not found in encrypted data.")