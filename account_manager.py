import os
import json
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

USER_DATA_FOLDER = "user_data"

class AccountManager:
    def __init__(self):
        if not os.path.exists(USER_DATA_FOLDER):
            os.makedirs(USER_DATA_FOLDER)
        self.current_user = None
        self.master_key = None

    def _derive_master_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def create_account(self, username, password):
        user_folder = os.path.join(USER_DATA_FOLDER, username)
        if os.path.exists(user_folder):
            raise Exception("Account already exists.")
        os.makedirs(user_folder)
        
        salt = os.urandom(16)
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        master_key = self._derive_master_key(password, salt)

        account_data = {
            "username": username,
            "password": hashed_password.decode(),
            "salt": base64.urlsafe_b64encode(salt).decode()
        }
        with open(os.path.join(user_folder, 'account.json'), 'w') as f:
            json.dump(account_data, f)

        self.current_user = username
        self.master_key = master_key
        return True

    def login(self, username, password):
        user_folder = os.path.join(USER_DATA_FOLDER, username)
        if not os.path.exists(user_folder):
            raise Exception("Account does not exist.")
        
        with open(os.path.join(user_folder, 'account.json'), 'r') as f:
            account_data = json.load(f)

        if bcrypt.checkpw(password.encode(), account_data["password"].encode()):
            self.current_user = username
            salt = base64.urlsafe_b64decode(account_data["salt"])
            self.master_key = self._derive_master_key(password, salt)
            return True
        else:
            raise Exception("Invalid username or password.")

    def get_user_folder(self):
        if not self.current_user:
            raise Exception("No user logged in.")
        return os.path.join(USER_DATA_FOLDER, self.current_user)