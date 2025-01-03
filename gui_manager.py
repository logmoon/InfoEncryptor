import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from encryption_manager import EncryptionManager
from account_manager import AccountManager
import os
import time
import threading

class GUIManager:
    def __init__(self, root):
        self.root = root
        self.root.title("InfoEncryptor 2.0")
        
        # Initialize managers
        self.account_manager = AccountManager('supabase-credentials.json')
        self.encryption_manager = EncryptionManager()
        
        # Configure resizing behavior for the main window
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        self.show_login_screen()

    def show_login_screen(self):
        """Show the login screen"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.login_frame = ttk.Frame(self.root, padding="20")
        self.login_frame.pack(expand=True)
        
        # Title
        title_label = ttk.Label(self.login_frame, text="InfoEncryptor 2.0", 
                              font=("Helvetica", 24, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Email field
        ttk.Label(self.login_frame, text="Email:").pack(pady=5)
        self.email_var = tk.StringVar()
        email_entry = ttk.Entry(self.login_frame, textvariable=self.email_var, width=40)
        email_entry.pack(pady=5)
        
        # Password field
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(self.login_frame, textvariable=self.password_var, 
                                 show="*", width=40)
        password_entry.pack(pady=5)
        
        # Buttons
        ttk.Button(self.login_frame, text="Login", 
                  command=self.login_action, width=30).pack(pady=10)
        ttk.Button(self.login_frame, text="Create Account", 
                  command=self.signup_action, width=30).pack(pady=10)

    def show_main_interface(self):
        """Show the main interface"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Top frame for user info and status
        top_frame = ttk.Frame(self.root)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        top_frame.columnconfigure(1, weight=1)  # Make the middle column expand
        
        # User label (left)
        self.user_label = ttk.Label(top_frame, 
                                  text=f"Logged in as: {self.account_manager.get_current_user()}", 
                                  foreground="green")
        self.user_label.grid(row=0, column=0, padx=(0, 20))
        
        # Status label (middle)
        self.status_label = ttk.Label(top_frame, text="Ready", foreground="green")
        self.status_label.grid(row=0, column=1, sticky="w")
        
        # Logout button (right)
        ttk.Button(top_frame, text="Logout", 
                  command=self.logout_action).grid(row=0, column=2)
        
        # Main content
        content_frame = ttk.Frame(self.root)
        content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(1, weight=1)
        
        # Buttons frame
        btn_frame = ttk.Frame(content_frame)
        btn_frame.grid(row=0, column=0, pady=10)
        
        ttk.Button(btn_frame, text="Encrypt New Folder", 
                  command=self.encrypt_action, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh", 
                  command=self.update_file_list, width=10).pack(side=tk.LEFT, padx=5)
        
        # Files list
        list_frame = ttk.LabelFrame(content_frame, text="Encrypted Folders", padding="10")
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Create treeview with scrollbar
        self.files_tree = ttk.Treeview(list_frame, 
                                     columns=("name", "size", "date"), 
                                     show="headings", 
                                     selectmode="browse")
        self.files_tree.heading("name", text="Folder Name")
        self.files_tree.heading("size", text="Size")
        self.files_tree.heading("date", text="Date")
        self.files_tree.column("name", width=200)
        self.files_tree.column("size", width=100)
        self.files_tree.column("date", width=100)
        self.files_tree.grid(row=0, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, 
                                command=self.files_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.files_tree.configure(yscrollcommand=scrollbar.set)
        
        # Context menu for files
        self.create_context_menu()
        
        # Update the file list
        self.update_file_list()

    def create_context_menu(self):
        """Create right-click context menu for files"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Decrypt", command=self.decrypt_action)
        self.context_menu.add_command(label="Delete", command=self.delete_action)
        
        self.files_tree.bind("<Button-3>", self.show_context_menu)
        self.files_tree.bind("<Double-1>", lambda e: self.decrypt_action())

    def show_context_menu(self, event):
        """Show the context menu on right-click"""
        try:
            self.files_tree.selection_set(self.files_tree.identify_row(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def run_in_thread(self, func, success_msg=None, error_msg=None):
        """Run a function in a separate thread with status updates"""
        def wrapper():
            try:
                result = func()
                if success_msg:
                    self.root.after(0, lambda: self.status_label.config(
                        text=success_msg, foreground="green"))
                self.root.after(0, self.update_file_list)
                return result
            except Exception as e:
                error = str(e)
                self.root.after(0, lambda: self.status_label.config(
                    text=f"{error_msg}: {error}" if error_msg else error, 
                    foreground="red"))
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", f"{error_msg}: {error}" if error_msg else error))
        
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()
        return thread

    def update_file_list(self):
        """Update the list of encrypted files"""
        def update_task():
            # Get files from cloud
            files, error = self.account_manager.cloud_manager.list_encrypted_files()
            if error:
                raise Exception(error)
            
            def update_ui():
                # Clear existing items
                for item in self.files_tree.get_children():
                    self.files_tree.delete(item)
                
                # Add files to treeview
                for file in files:
                    size = f"{file['size'] / 1024:.1f} KB"
                    date = file['created_at'].split('T')[0]
                    self.files_tree.insert("", "end", values=(
                        file['folder_name'], size, date))
                
                self.status_label.config(
                    text=f"Found {len(files)} encrypted folders", 
                    foreground="green")
            
            self.root.after(0, update_ui)
        
        self.run_in_thread(update_task, error_msg="Failed to update file list")

    def login_action(self):
        """Handle login button click"""
        email = self.email_var.get()
        password = self.password_var.get()
        
        success, error = self.account_manager.login(email, password)
        if success:
            self.show_main_interface()
        else:
            messagebox.showerror("Error", f"Login failed: {error}")

    def signup_action(self):
        """Handle signup button click"""
        email = self.email_var.get()
        password = self.password_var.get()
        
        success, error = self.account_manager.signup(email, password)
        if success:
            self.show_main_interface()
        else:
            messagebox.showerror("Error", f"Signup failed: {error}")

    def logout_action(self):
        """Handle logout button click"""
        self.account_manager.logout()
        self.show_login_screen()

    def encrypt_action(self):
        """Handle encrypt folder button click"""
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folder_path:
            return

        folder_name = os.path.basename(folder_path)
        self.status_label.config(text="Encrypting folder...", foreground="yellow")
        
        def encrypt_task():
            # Compress folder to memory
            compressed_data = self.encryption_manager.compress_folder(folder_path)
            
            # Encrypt the compressed data
            encrypted_data = self.encryption_manager.encrypt_data(compressed_data)
            
            # Upload to cloud
            success, error = self.account_manager.cloud_manager.upload_encrypted_data(
                folder_name, encrypted_data)
            if not success:
                raise Exception(error)
        
        self.run_in_thread(
            encrypt_task,
            success_msg="Folder encrypted and uploaded successfully",
            error_msg="Encryption failed"
        )

    def decrypt_action(self):
        """Handle decrypt folder button click"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder to decrypt")
            return
            
        folder_name = self.files_tree.item(selection[0])['values'][0]  # Get from first column
        output_path = filedialog.askdirectory(title="Select Where to Decrypt")
        if not output_path:
            return
            
        self.status_label.config(text="Downloading encrypted data...", 
                              foreground="yellow")
        
        def decrypt_task():
            # Download from cloud
            encrypted_data, error = self.account_manager.cloud_manager.download_encrypted_data(
                folder_name)
            if error:
                raise Exception(error)
            
            # Decrypt data
            self.root.after(0, lambda: self.status_label.config(
                text="Decrypting data...", foreground="yellow"))
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            
            # Extract archive
            self.encryption_manager.extract_folder(decrypted_data, output_path)
        
        self.run_in_thread(
            decrypt_task,
            success_msg="Folder decrypted successfully",
            error_msg="Decryption failed"
        )

    def delete_action(self):
        """Handle delete folder button click"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a folder to delete")
            return
            
        folder_name = self.files_tree.item(selection[0])['values'][0]  # Get from first column
        
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete {folder_name}?"):
            self.status_label.config(text="Deleting folder...", foreground="yellow")
            
            def delete_task():
                success, error = self.account_manager.cloud_manager.delete_encrypted_data(
                    folder_name)
                if not success:
                    raise Exception(error)
            
            self.run_in_thread(
                delete_task,
                success_msg="Folder deleted successfully",
                error_msg="Delete failed"
            )

def main():
    root = tb.Window(themename="darkly")
    app = GUIManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()
