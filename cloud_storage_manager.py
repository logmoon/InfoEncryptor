from supabase import create_client, Client
import os
import json
from typing import Optional, Dict, List, Tuple
import threading
import time
import base64
import uuid

class CloudStorageManager:
    def __init__(self, config_path: str):
        """Initialize Supabase with project credentials"""
        with open(config_path, 'r') as f:
            config = json.load(f)
            self.supabase_url = config.get('supabase_url')
            self.supabase_key = config.get('supabase_key')
            self.client = self.create_client()
        
        self._current_user = None

    def create_client(self) -> Client:
        """Create a fresh Supabase client"""
        return create_client(self.supabase_url, self.supabase_key)

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
