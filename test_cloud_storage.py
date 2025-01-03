import os
from account_manager import AccountManager
from encryption_manager import EncryptionManager
from cloud_storage_manager import CloudStorageManager

def test_cloud_storage():
    print("Starting cloud storage test...")
    
    # Initialize cloud manager directly
    config_path = os.path.join(os.path.dirname(__file__), 'supabase-credentials.json')
    if not os.path.exists(config_path):
        print("❌ Failed: supabase-credentials.json not found")
        print("Please create this file with your Supabase credentials:")
        print("""
{
    "supabase_url": "YOUR_SUPABASE_PROJECT_URL",
    "supabase_key": "YOUR_SUPABASE_ANON_KEY"
}
        """)
        return
        
    cloud_manager = CloudStorageManager(config_path)
    
    # Test 1: Check Supabase connection
    print("\nTest 1: Checking Supabase connection...")
    try:
        # Simple query to check connection
        cloud_manager.supabase.table('encrypted_files').select("*").limit(1).execute()
        print("✓ Success: Supabase connection working")
    except Exception as e:
        print(f"❌ Failed: Could not connect to Supabase. Error: {str(e)}")
        return
    
    # Test 2: Upload test
    print("\nTest 2: Testing file upload...")
    test_user_id = "test_user"
    test_file_id = "test_file"
    test_data = b"This is a test encrypted file content"
    
    upload_success = cloud_manager.upload_encrypted_data(
        test_user_id,
        test_file_id,
        test_data
    )
    
    if not upload_success:
        print("❌ Failed: Could not upload test file")
        return
    print("✓ Success: Test file uploaded")
    
    # Test 3: Download test
    print("\nTest 3: Testing file download...")
    downloaded_data = cloud_manager.download_encrypted_data(
        test_user_id,
        test_file_id
    )
    
    if downloaded_data != test_data:
        print("❌ Failed: Downloaded data doesn't match uploaded data")
        return
    print("✓ Success: File download matches original")
    
    # Test 4: List files test
    print("\nTest 4: Testing file listing...")
    files = cloud_manager.list_user_files(test_user_id)
    if not files:
        print("❌ Failed: Could not list files")
        return
    print("✓ Success: File listing working")
    print(f"Found files: {files}")
    
    # Test 5: Sync callback test
    print("\nTest 5: Testing sync service...")
    def sync_callback(data):
        print(f"Sync callback received data: {data}")
    
    cloud_manager.start_sync_service(test_user_id, sync_callback)
    print("✓ Success: Sync service started")
    
    print("\nAll tests completed successfully! 🎉")
    print("Your cloud storage integration is working correctly.")

if __name__ == "__main__":
    test_cloud_storage()
