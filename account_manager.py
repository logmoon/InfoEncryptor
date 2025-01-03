import os
import json
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cloud_storage_manager import CloudStorageManager
from typing import Tuple, Optional

USER_DATA_FOLDER = "user_data"

class AccountManager:
    def __init__(self, supabase_config_path: str):
        """Initialize the account manager"""
        self.cloud_manager = CloudStorageManager(supabase_config_path)
        self.current_user = None

    def signup(self, email: str, password: str) -> Tuple[bool, str]:
        """Sign up a new user"""
        success, error = self.cloud_manager.signup(email, password)
        if success:
            self.current_user = email
        return success, error

    def login(self, email: str, password: str) -> Tuple[bool, str]:
        """Log in an existing user"""
        success, error = self.cloud_manager.login(email, password)
        if success:
            self.current_user = email
        return success, error

    def logout(self):
        """Log out the current user"""
        self.cloud_manager.logout()
        self.current_user = None

    def get_current_user(self) -> Optional[str]:
        """Get the current user's email"""
        return self.current_user