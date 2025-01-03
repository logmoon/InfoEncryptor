import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from encryption_manager import EncryptionManager
from account_manager import AccountManager
import os
import time
import threading
from functools import partial
from typing import List, Dict, Optional

class BackgroundTask:
    def __init__(self, target, on_complete=None, on_error=None):
        self.target = target
        self.on_complete = on_complete
        self.on_error = on_error
        
    def run(self):
        def wrapper():
            try:
                result = self.target()
                if self.on_complete:
                    # Schedule callback on main thread
                    tk._default_root.after(0, lambda r=result: self.on_complete(r))
            except Exception as e:
                if self.on_error:
                    error_msg = str(e)
                    # Schedule error handler on main thread
                    tk._default_root.after(0, lambda msg=error_msg: self.on_error(msg))
        
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()

class GUIManager:
    def __init__(self, root):
        self.root = root
        self.root.title("InfoEncryptor 2.0")
        
        # Initialize managers
        self.account_manager = AccountManager('supabase-credentials.json')
        
        # Login entries cache
        self._login_entries = None
        
        # Configure root window
        self.root.minsize(600, 400)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Show login screen
        self.show_login_screen()

    def get_login_entries(self) -> List[Dict]:
        """Get cached login entries or load from cloud"""
        if self._login_entries is None:
            self._login_entries = self.account_manager.cloud_manager.get_login_entries()
        return self._login_entries
        
    def save_login_entries(self, entries: List[Dict]) -> bool:
        """Save login entries to cloud and update cache"""
        if self.account_manager.cloud_manager.save_login_entries(entries):
            self._login_entries = entries
            return True
        return False
        
    def add_login_entry(self, entry: Dict) -> bool:
        """Add a new login entry"""
        entries = self.get_login_entries()
        entries.append(entry)
        return self.save_login_entries(entries)
        
    def update_login_entry(self, index: int, entry: Dict) -> bool:
        """Update an existing login entry"""
        entries = self.get_login_entries()
        if 0 <= index < len(entries):
            entries[index] = entry
            return self.save_login_entries(entries)
        return False
        
    def delete_login_entry(self, index: int) -> bool:
        """Delete a login entry"""
        entries = self.get_login_entries()
        if 0 <= index < len(entries):
            entries.pop(index)
            return self.save_login_entries(entries)
        return False
        
    def show_login_screen(self):
        """Show the login screen"""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.pack(expand=True)
        
        # Title
        title_label = ttk.Label(login_frame, text="InfoEncryptor 2.0", 
                              font=("Helvetica", 24, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Stored logins
        logins = self.account_manager.cloud_manager.get_stored_logins()
        if logins:
            login_list = ttk.Frame(login_frame)
            login_list.pack(pady=(0, 20), fill="x")
            
            ttk.Label(login_list, text="Stored Logins:", 
                     font=("Helvetica", 10, "bold")).pack(anchor="w")
            
            for login in logins:
                login_item = ttk.Frame(login_list)
                login_item.pack(fill="x", pady=2)
                
                # Email and last login
                last_login = login['last_login'].split('T')[0]
                info_text = f"{login['email']} (Last login: {last_login})"
                ttk.Label(login_item, text=info_text).pack(side="left")
                
                # Login button
                ttk.Button(login_item, text="Login", 
                          command=lambda e=login['email']: self.show_password_prompt(e))\
                    .pack(side="right")
        
        # Or login with new account
        ttk.Label(login_frame, text="Login with a new account:", 
                 font=("Helvetica", 10, "bold")).pack(pady=(0, 10))
        
        # Email field
        ttk.Label(login_frame, text="Email:").pack(pady=5)
        self.email_var = tk.StringVar()
        email_entry = ttk.Entry(login_frame, textvariable=self.email_var, width=40)
        email_entry.pack(pady=5)
        
        # Password field
        ttk.Label(login_frame, text="Password:").pack(pady=5)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(login_frame, textvariable=self.password_var, 
                                 show="*", width=40)
        password_entry.pack(pady=5)
        
        # Buttons
        ttk.Button(login_frame, text="Login", 
                  command=self.login_action, width=30).pack(pady=10)
        ttk.Button(login_frame, text="Create Account", 
                  command=self.signup_action, width=30).pack(pady=10)

    def show_password_prompt(self, email: str):
        """Show password prompt for stored login"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Password")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("300x200")
        dialog.resizable(False, False)
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(expand=True, fill="both")
        
        ttk.Label(frame, text=f"Enter password for {email}:").pack(pady=5)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*")
        password_entry.pack(pady=10)
        password_entry.focus()
        
        def login():
            success = self.login_with_stored(email, password_var.get())
            if success:
                dialog.destroy()
                self.show_main_interface()
            else:
                messagebox.showerror("Error", "Invalid password")
        
        ttk.Button(frame, text="Login", command=login).pack(pady=10)
        
        # Bind Enter key
        dialog.bind("<Return>", lambda e: login())
        
        # Handle dialog close
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)

    def login_with_stored(self, email: str, password: str) -> bool:
        """Login with stored credentials"""
        login_info = self.account_manager.cloud_manager.get_login_info(email)
        if not login_info:
            return False
            
        if not self.account_manager.cloud_manager.verify_password(
            login_info['password_hash'], password):
            return False
            
        # Login with Supabase
        success, error = self.account_manager.login(email, password)
        if success:
            return True
            
        messagebox.showerror("Error", f"Login failed: {error}")
        return False

    def show_main_interface(self):
        """Show the main interface"""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Top frame for user info and status
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(0, weight=1)
        
        # User info (left aligned)
        info_frame = ttk.Frame(top_frame)
        info_frame.grid(row=0, column=0, sticky="w")
        
        user_label = ttk.Label(info_frame, 
                             text=f"Logged in as: {self.account_manager.get_current_user()}", 
                             font=("Helvetica", 10))
        user_label.pack(anchor="w")
        
        self.status_label = ttk.Label(info_frame, text="Ready", 
                                    font=("Helvetica", 9), foreground="green")
        self.status_label.pack(anchor="w", pady=(5, 0))
        
        # Logout button (right aligned)
        ttk.Button(top_frame, text="Logout", 
                  command=self.logout_action).grid(row=0, column=1, sticky="e")
        
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # Folders tab
        folders_tab = ttk.Frame(notebook, padding=10)
        notebook.add(folders_tab, text="Encrypted Folders")
        
        # Encrypt button at top
        ttk.Button(folders_tab, text="Encrypt New Folder", 
                  command=self.encrypt_action).pack(pady=(0, 10))
        
        # Scrollable frame for folder list
        canvas = tk.Canvas(folders_tab)
        scrollbar = ttk.Scrollbar(folders_tab, orient="vertical", command=canvas.yview)
        self.folders_frame = ttk.Frame(canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Create window in canvas for folders
        canvas_frame = canvas.create_window((0, 0), window=self.folders_frame, anchor="nw")
        
        # Configure canvas scrolling
        def configure_scroll(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_frame, width=canvas.winfo_width())
        
        self.folders_frame.bind("<Configure>", configure_scroll)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_frame, width=canvas.winfo_width()))
        
        # Update folder list
        self.update_file_list()
        
        # Logins tab
        logins_tab = ttk.Frame(notebook, padding=10)
        notebook.add(logins_tab, text="Login Entries")
        
        self.show_login_entries_tab(logins_tab)

    def create_login_entry_frame(self, parent, entry: Dict, index: int):
        """Create a frame for a single login entry with improved layout"""
        # Main frame for the entry
        entry_frame = ttk.Frame(parent)
        entry_frame.pack(fill="x", padx=10, pady=5)
        
        # Service name header
        service_label = ttk.Label(
            entry_frame, 
            text=entry["service"],
            font=("TkDefaultFont", 12, "bold"),
            justify="left"
        )
        service_label.pack(anchor="w", pady=(5, 2))
        
        # Info frame for username and email
        info_frame = ttk.Frame(entry_frame)
        info_frame.pack(fill="x", padx=20)
        
        # Username
        username_frame = ttk.Frame(info_frame)
        username_frame.pack(fill="x", pady=2)
        ttk.Label(username_frame, text="Username:", width=10).pack(side="left")
        ttk.Label(username_frame, text=entry["username"]).pack(side="left")
        
        # Email
        email_frame = ttk.Frame(info_frame)
        email_frame.pack(fill="x", pady=2)
        ttk.Label(email_frame, text="Email:", width=10).pack(side="left")
        ttk.Label(email_frame, text=entry["email"]).pack(side="left")
        
        # Buttons frame
        btn_frame = ttk.Frame(entry_frame)
        btn_frame.pack(fill="x", padx=20, pady=(5, 0))
        
        def copy_to_clipboard(text):
            """Copy text to clipboard and show feedback"""
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Copied to clipboard", foreground="green")
            
        ttk.Button(btn_frame, text="Copy Email", 
                  command=lambda: copy_to_clipboard(entry["email"]))\
            .pack(side="left", padx=2)
            
        ttk.Button(btn_frame, text="Copy Username", 
                  command=lambda: copy_to_clipboard(entry["username"]))\
            .pack(side="left", padx=2)
            
        ttk.Button(btn_frame, text="Delete", 
                  command=lambda: self.handle_delete_login_entry(index))\
            .pack(side="left", padx=2)
            
        # Separator
        ttk.Separator(parent, orient="horizontal")\
            .pack(fill="x", padx=5, pady=(10, 0))
            
    def show_login_entries_tab(self, tab):
        """Show the login entries tab with scrollable content"""
        # Configure tab to expand
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)  # Row 1 will contain the scrollable frame
        
        # Add entry button at top
        ttk.Button(tab, text="Add Login Entry", 
                  command=self.show_login_entry_dialog).grid(row=0, pady=(0, 10))
        
        # Main container
        main_frame = ttk.Frame(tab)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Create canvas and scrollbar for scrolling
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        self.entries_frame = ttk.Frame(canvas)
        
        # Configure scrolling
        self.entries_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Configure canvas to expand with window
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create window in canvas that expands horizontally
        self.entries_frame.bind('<Configure>', lambda e: canvas.configure(width=e.width))
        canvas_window = canvas.create_window((0, 0), window=self.entries_frame, anchor="nw")
        
        # Make the canvas window expand horizontally with the canvas
        def configure_canvas_window(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind('<Configure>', configure_canvas_window)
        
        # Status label at bottom
        self.status_label = ttk.Label(tab, text="")
        self.status_label.grid(row=2, pady=5)
        
        # Initial update
        self.update_login_entries()
        
    def create_login_entry_item(self, index: int, entry: Dict):
        """Create a frame for a single login entry"""
        # Main frame for the entry
        entry_frame = ttk.Frame(self.entries_frame)
        entry_frame.pack(fill="x", padx=10, pady=5)
        entry_frame.columnconfigure(1, weight=1)  # Make info frame expand
        
        # Service name header
        service_label = ttk.Label(
            entry_frame, 
            text=entry["service"],
            font=("TkDefaultFont", 12, "bold"),
            justify="left"
        )
        service_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(5, 2))
        
        # Info frame for username and email
        info_frame = ttk.Frame(entry_frame)
        info_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20)
        info_frame.columnconfigure(1, weight=1)  # Make value labels expand
        
        # Username
        ttk.Label(info_frame, text="Username:", width=10).grid(row=0, column=0, sticky="w", pady=2)
        ttk.Label(info_frame, text=entry["username"]).grid(row=0, column=1, sticky="w")
        
        # Email
        ttk.Label(info_frame, text="Email:", width=10).grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(info_frame, text=entry["email"]).grid(row=1, column=1, sticky="w")
        
        # Buttons frame
        btn_frame = ttk.Frame(entry_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=20, pady=(5, 0))
        
        def copy_to_clipboard(text):
            """Copy text to clipboard and show feedback"""
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Copied to clipboard", foreground="green")
            
        # Use grid instead of pack for buttons to ensure they're all visible
        buttons = [
            ("Copy Email", lambda: copy_to_clipboard(entry["email"])),
            ("Copy Username", lambda: copy_to_clipboard(entry["username"])),
            ("Copy Password", lambda: copy_to_clipboard(entry["password"])),
            ("Edit", lambda: self.show_login_entry_dialog({**entry, "index": index})),
            ("Delete", lambda: self.handle_delete_login_entry(index))
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(btn_frame, text=text, command=command)\
                .grid(row=0, column=i, padx=2)
            
        # Separator
        ttk.Separator(self.entries_frame, orient="horizontal")\
            .pack(fill="x", padx=5, pady=(10, 0))
            
    def update_login_entries(self):
        """Update the list of login entries"""
        # Clear existing entries
        for widget in self.entries_frame.winfo_children():
            widget.destroy()
        
        # Add entries
        entries = self.get_login_entries()
        for i, entry in enumerate(entries):
            self.create_login_entry_item(i, entry)
            
        self.status_label.config(text=f"Found {len(entries)} login entries", 
                               foreground="green")

    def create_folder_item(self, folder_name: str, size: str, date: str):
        """Create a frame for a single folder item"""
        frame = ttk.Frame(self.folders_frame)
        frame.pack(fill="x", pady=2)
        frame.columnconfigure(1, weight=1)
        
        # Folder info
        info_text = f"{folder_name} ({size}, {date})"
        ttk.Label(frame, text=info_text).grid(row=0, column=0, sticky="w", padx=(5, 10))
        
        # Buttons frame
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=1, sticky="e")
        
        ttk.Button(btn_frame, text="Decrypt", 
                  command=partial(self.decrypt_action, folder_name)).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Delete", 
                  command=partial(self.delete_action, folder_name)).pack(side="left", padx=2)

    def update_file_list(self):
        """Update the list of encrypted files"""
        def fetch_files():
            return self.account_manager.cloud_manager.list_encrypted_files()
            
        def update_ui(result):
            files, error = result
            if error:
                self.status_label.config(text=f"Error: {error}", foreground="red")
                return
                
            # Clear existing folders
            for widget in self.folders_frame.winfo_children():
                widget.destroy()
            
            # Add folder items
            for file in files:
                size = f"{file['size'] / 1024:.1f} KB"
                date = file['created_at'].split('T')[0]
                self.create_folder_item(file['folder_name'], size, date)
            
            self.status_label.config(text=f"Found {len(files)} encrypted folders", 
                                  foreground="green")
                                  
        def on_error(error):
            self.status_label.config(text=f"Error: {error}", foreground="red")
            
        # Run update in background
        BackgroundTask(fetch_files, update_ui, on_error).run()

    def encrypt_action(self):
        """Handle encrypt folder button click"""
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folder_path:
            return

        folder_name = os.path.basename(folder_path)
        self.status_label.config(text="Encrypting folder...", foreground="yellow")
        
        def encrypt():
            compressed_data = self.account_manager.cloud_manager.encryption_manager.compress_folder(folder_path)
            encrypted_data = self.account_manager.cloud_manager.encryption_manager.encrypt_data(compressed_data)
            return self.account_manager.cloud_manager.upload_encrypted_data(folder_name, encrypted_data)
            
        def on_complete(result):
            success, error = result
            if success:
                self.status_label.config(text="Folder encrypted and uploaded successfully", 
                                      foreground="green")
                self.update_file_list()
            else:
                self.status_label.config(text=f"Upload failed: {error}", 
                                      foreground="red")
                
        def on_error(error):
            self.status_label.config(text=f"Error: {error}", foreground="red")
            messagebox.showerror("Error", f"Encryption failed: {error}")
            
        BackgroundTask(encrypt, on_complete, on_error).run()

    def decrypt_action(self, folder_name):
        """Handle decrypt folder button click"""
        output_path = filedialog.askdirectory(title="Select Where to Decrypt")
        if not output_path:
            return
            
        self.status_label.config(text="Downloading encrypted data...", 
                              foreground="yellow")
        
        def decrypt():
            encrypted_data, error = self.account_manager.cloud_manager.download_encrypted_data(folder_name)
            if error:
                raise Exception(error)
                
            self.status_label.config(text="Decrypting data...", foreground="yellow")
            decrypted_data = self.account_manager.cloud_manager.encryption_manager.decrypt_data(encrypted_data)
            self.account_manager.cloud_manager.encryption_manager.extract_folder(decrypted_data, output_path)
            return True
            
        def on_complete(_):
            self.status_label.config(text="Folder decrypted successfully", 
                                  foreground="green")
            
        def on_error(error):
            self.status_label.config(text=f"Error: {error}", foreground="red")
            messagebox.showerror("Error", f"Decryption failed: {error}")
            
        BackgroundTask(decrypt, on_complete, on_error).run()

    def delete_action(self, folder_name):
        """Handle delete folder button click"""
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete {folder_name}?"):
                             
            def delete():
                return self.account_manager.cloud_manager.delete_encrypted_data(folder_name)
                
            def on_complete(result):
                success, error = result
                if success:
                    self.status_label.config(text="Folder deleted successfully", 
                                          foreground="green")
                    self.update_file_list()
                else:
                    self.status_label.config(text=f"Delete failed: {error}", 
                                          foreground="red")
                    messagebox.showerror("Error", f"Delete failed: {error}")
                    
            def on_error(error):
                self.status_label.config(text=f"Error: {error}", foreground="red")
                messagebox.showerror("Error", f"Delete failed: {error}")
                
            BackgroundTask(delete, on_complete, on_error).run()

    def login_action(self):
        """Handle login button click"""
        email = self.email_var.get()
        password = self.password_var.get()
        
        success, error = self.account_manager.login(email, password)
        if success:
            # Store login info
            self.account_manager.cloud_manager.store_login_info(email, password)
            self.show_main_interface()
        else:
            messagebox.showerror("Error", f"Login failed: {error}")

    def signup_action(self):
        """Handle signup button click"""
        email = self.email_var.get()
        password = self.password_var.get()
        
        success, error = self.account_manager.signup(email, password)
        if success:
            # Store login info
            self.account_manager.cloud_manager.store_login_info(email, password)
            self.show_main_interface()
        else:
            messagebox.showerror("Error", f"Signup failed: {error}")

    def logout_action(self):
        """Handle logout button click"""
        self._login_entries = None  # Clear cache
        self.account_manager.logout()
        self.show_login_screen()

    def handle_delete_login_entry(self, index: int):
        """Show dialog to confirm and delete a login entry"""
        if messagebox.askyesno("Confirm Delete", 
                             "Are you sure you want to delete this login entry?"):
            entries = self.get_login_entries()
            entries.pop(index)
            if self.save_login_entries(entries):
                self.update_login_entries()
            else:
                messagebox.showerror("Error", "Failed to delete login entry")

    def show_login_entry_dialog(self, entry_data=None):
        """Show dialog for adding/editing login entry"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Login Entry" if entry_data is None else "Edit Login Entry")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("400x550")
        dialog.resizable(False, False)
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(expand=True, fill="both")
        
        # Form fields
        ttk.Label(frame, text="Service:").pack(anchor="w", pady=(0, 5))
        service_var = tk.StringVar(value=entry_data["service"] if entry_data else "")
        ttk.Entry(frame, textvariable=service_var).pack(fill="x", pady=(0, 10))
        
        ttk.Label(frame, text="Username:").pack(anchor="w", pady=(0, 5))
        username_var = tk.StringVar(value=entry_data["username"] if entry_data else "")
        ttk.Entry(frame, textvariable=username_var).pack(fill="x", pady=(0, 10))
        
        ttk.Label(frame, text="Password:").pack(anchor="w", pady=(0, 5))
        password_var = tk.StringVar(value=entry_data["password"] if entry_data else "")
        ttk.Entry(frame, textvariable=password_var, show="*").pack(fill="x", pady=(0, 10))
        
        ttk.Label(frame, text="Email:").pack(anchor="w", pady=(0, 5))
        email_var = tk.StringVar(value=entry_data["email"] if entry_data else "")
        ttk.Entry(frame, textvariable=email_var).pack(fill="x", pady=(0, 10))
        
        ttk.Label(frame, text="Notes:").pack(anchor="w", pady=(0, 5))
        notes_var = tk.StringVar(value=entry_data["notes"] if entry_data else "")
        notes_entry = tk.Text(frame, height=4, width=40)
        notes_entry.pack(fill="x", pady=(0, 10))
        if entry_data and entry_data["notes"]:
            notes_entry.insert("1.0", entry_data["notes"])
        
        def save():
            entry = {
                "service": service_var.get(),
                "username": username_var.get(),
                "password": password_var.get(),
                "email": email_var.get(),
                "notes": notes_entry.get("1.0", "end-1c")
            }
            
            if not entry["service"] or not entry["username"] or not entry["password"]:
                messagebox.showwarning("Warning", 
                                     "Service, username and password are required")
                return
            
            if entry_data:
                # Update existing entry
                success = self.update_login_entry(
                    entry_data["index"],
                    entry
                )
            else:
                # Add new entry
                success = self.add_login_entry(
                    entry
                )
            
            if success:
                dialog.destroy()
                self.update_login_entries()
            else:
                messagebox.showerror("Error", "Failed to save login entry")
        
        ttk.Button(frame, text="Save", command=save).pack(pady=10)

def main():
    root = tb.Window(themename="darkly")
    app = GUIManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()
