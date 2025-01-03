from supabase import create_client, Client
import os
import json
from typing import Optional, Dict, List, Tuple
import threading
import time
import base64
import uuid
import hashlib
import datetime

class CloudStorageManager:
    def __init__(self, config_path: str, encryption_manager=None):
        """Initialize cloud storage manager"""
        # Load config
        with open(config_path) as f:
            config = json.load(f)
            
        # Initialize client
        self.client = create_client(
            config['supabase_url'],
            config['supabase_key']
        )
        
        self._current_user = None
        self.encryption_manager = encryption_manager

    def create_client(self) -> Client:
        """Create a fresh Supabase client"""
        return create_client(self.client.url, self.client.key)

    def signup(self, email: str, password: str) -> Tuple[bool, str]:
        """Sign up a new user"""
        try:
            response = self.client.auth.sign_up({
                "email": email,
                "password": password
            })
            if response.user:
                self._current_user = response.user
                return True, ""
            return False, "Signup failed"
        except Exception as e:
            return False, str(e)

    def login(self, email: str, password: str) -> Tuple[bool, str]:
        """Log in an existing user"""
        try:
            response = self.client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            if response.user:
                self._current_user = response.user
                return True, ""
            return False, "Login failed"
        except Exception as e:
            return False, str(e)

    def logout(self):
        """Log out the current user"""
        try:
            self.client.auth.sign_out()
            self._current_user = None
        except Exception as e:
            print(f"Logout error: {str(e)}")

    def get_user_id(self) -> Optional[str]:
        """Get the current user's ID"""
        return self._current_user.id if self._current_user else None

    def upload_encrypted_data(self, folder_name: str, encrypted_data: bytes) -> Tuple[bool, str]:
        """Upload encrypted data to Supabase"""
        if not self._current_user:
            return False, "Not authenticated"

        try:
            # Convert bytes to base64 for storage
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Generate a unique file ID
            file_id = str(uuid.uuid4())
            
            # Store in the encrypted_files table
            data = {
                'user_id': self._current_user.id,
                'file_id': f"{folder_name}_{file_id}",  # Combine folder name with UUID for uniqueness
                'encrypted_data': encoded_data,
                'size': len(encrypted_data)
            }
            
            result = self.client.table('encrypted_files').upsert(data).execute()
            return True, ""
        except Exception as e:
            return False, str(e)

    def download_encrypted_data(self, folder_name: str) -> Tuple[Optional[bytes], str]:
        """Download encrypted data from Supabase"""
        if not self._current_user:
            return None, "Not authenticated"

        try:
            # Query using LIKE to match the folder name prefix
            result = self.client.table('encrypted_files')\
                .select('encrypted_data')\
                .eq('user_id', self._current_user.id)\
                .like('file_id', f"{folder_name}_%")\
                .limit(1)\
                .execute()
            
            if result.data:
                # Convert base64 back to bytes
                encoded_data = result.data[0]['encrypted_data']
                return base64.b64decode(encoded_data), ""
            return None, "File not found"
        except Exception as e:
            return None, str(e)

    def delete_encrypted_data(self, folder_name: str) -> Tuple[bool, str]:
        """Delete encrypted data from Supabase"""
        if not self._current_user:
            return False, "Not authenticated"

        try:
            self.client.table('encrypted_files')\
                .delete()\
                .eq('user_id', self._current_user.id)\
                .like('file_id', f"{folder_name}_%")\
                .execute()
            return True, ""
        except Exception as e:
            return False, str(e)

    def list_encrypted_files(self) -> Tuple[List[Dict], str]:
        """List all encrypted files for the current user"""
        if not self._current_user:
            return [], "Not authenticated"

        try:
            result = self.client.table('encrypted_files')\
                .select('file_id,size,created_at')\
                .eq('user_id', self._current_user.id)\
                .execute()
            
            # Process the results to extract folder names
            files = []
            for item in result.data:
                folder_name = item['file_id'].split('_')[0]  # Get folder name from file_id
                files.append({
                    'folder_name': folder_name,
                    'size': item['size'],
                    'created_at': item['created_at']
                })
            
            return files, ""
        except Exception as e:
            return [], str(e)

    def get_encryption_key(self) -> Optional[bytes]:
        """Get the encryption key for the current user"""
        if not self._current_user:
            return None
            
        try:
            result = self.client.table('user_keys')\
                .select('key_data')\
                .eq('user_id', self._current_user.id)\
                .limit(1)\
                .execute()
                
            if result.data:
                # Decode base64 key
                return base64.b64decode(result.data[0]['key_data'])
            return None
        except Exception as e:
            print(f"Error getting key: {str(e)}")
            return None
            
    def store_encryption_key(self, key_data: bytes) -> bool:
        """Store the encryption key for the current user"""
        if not self._current_user:
            return False
            
        try:
            # Convert key to base64 for storage
            encoded_key = base64.b64encode(key_data).decode('utf-8')
            
            data = {
                'user_id': self._current_user.id,
                'key_data': encoded_key
            }
            
            self.client.table('user_keys').upsert(data).execute()
            return True
        except Exception as e:
            print(f"Error storing key: {str(e)}")
            return False

    def store_login_info(self, email: str, password: str) -> bool:
        """Store login information for the current user"""
        if not self._current_user:
            return False
            
        try:
            # Hash password before storing
            password_hash = base64.b64encode(
                hashlib.sha256(password.encode()).digest()
            ).decode('utf-8')
            
            data = {
                'user_id': self._current_user.id,
                'email': email,
                'password_hash': password_hash,
                'last_login': datetime.datetime.utcnow().isoformat()
            }
            
            self.client.table('user_logins').upsert(data).execute()
            return True
        except Exception as e:
            print(f"Error storing login info: {str(e)}")
            return False
            
    def get_stored_logins(self) -> List[Dict]:
        """Get all stored login information"""
        try:
            result = self.client.table('user_logins')\
                .select('email,last_login')\
                .order('last_login', desc=True)\
                .execute()
                
            return result.data if result.data else []
        except Exception as e:
            print(f"Error getting logins: {str(e)}")
            return []
            
    def get_login_info(self, email: str) -> Optional[Dict]:
        """Get login information for a specific email"""
        try:
            result = self.client.table('user_logins')\
                .select('email,password_hash')\
                .eq('email', email)\
                .limit(1)\
                .execute()
                
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error getting login info: {str(e)}")
            return None
            
    def verify_password(self, stored_hash: str, password: str) -> bool:
        """Verify if a password matches the stored hash"""
        password_hash = base64.b64encode(
            hashlib.sha256(password.encode()).digest()
        ).decode('utf-8')
        return password_hash == stored_hash

    def upload_encrypted_data(self, filename: str, data: bytes) -> Tuple[bool, str]:
        """Upload encrypted data to cloud storage"""
        if not self._current_user:
            return False, "Not logged in"
            
        try:
            # Create metadata
            metadata = {
                'user_id': self._current_user.id,
                'filename': filename,
                'size': len(data),
                'last_modified': datetime.datetime.utcnow().isoformat()
            }
            
            # Upload data
            result = self.client.storage\
                .from_('encrypted_data')\
                .upload(
                    f"{self._current_user.id}/{filename}",
                    data,
                    {'upsert': True}
                )
                
            if result.error:
                return False, str(result.error)
                
            # Update metadata
            self.client.table('files')\
                .upsert(metadata)\
                .execute()
                
            return True, ""
        except Exception as e:
            return False, str(e)
            
    def get_login_entries(self) -> List[Dict]:
        """Get login entries from encrypted file"""
        if not self._current_user or not self.encryption_manager:
            return []
            
        try:
            # Check if login entries file exists
            result = self.client.table('encrypted_files')\
                .select('encrypted_data')\
                .eq('user_id', self._current_user.id)\
                .eq('file_id', 'login_entries')\
                .limit(1)\
                .execute()
                
            if not result.data:
                # Create empty login entries file
                empty_entries = []
                data = json.dumps(empty_entries).encode()
                encrypted_data = self.encryption_manager.encrypt_data(data)
                encoded_data = base64.b64encode(encrypted_data).decode()
                
                # Save to database
                self.client.table('encrypted_files').upsert({
                    'user_id': self._current_user.id,
                    'file_id': 'login_entries',
                    'encrypted_data': encoded_data,
                    'size': len(encrypted_data)
                }).execute()
                
                return empty_entries
                
            # Decrypt and parse data
            encrypted_data = base64.b64decode(result.data[0]['encrypted_data'])
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            print(f"Error getting login entries: {str(e)}")
            return []
            
    def save_login_entries(self, entries: List[Dict]) -> bool:
        """Save login entries to encrypted file"""
        if not self._current_user or not self.encryption_manager:
            return False
            
        try:
            # Encrypt entries
            data = json.dumps(entries).encode()
            encrypted_data = self.encryption_manager.encrypt_data(data)
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            # Delete existing entry if any
            self.client.table('encrypted_files')\
                .delete()\
                .eq('user_id', self._current_user.id)\
                .eq('file_id', 'login_entries')\
                .execute()
            
            # Insert new entry
            self.client.table('encrypted_files').insert({
                'user_id': self._current_user.id,
                'file_id': 'login_entries',
                'encrypted_data': encoded_data,
                'size': len(encrypted_data)
            }).execute()
            
            return True
            
        except Exception as e:
            print(f"Error saving login entries: {str(e)}")
            return False
