import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
from cryptography.fernet import Fernet
import bcrypt
import pyperclip  # For clipboard functionality

class PasswordManagerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Encryption setup
        self.key = b'fZ8wMjS5Q3K7vR2nL9mP6cT4xU1yE8oI3dF7gH2sA5B='
        self.fernet = Fernet(self.key)
        
        # Current user
        self.current_user = None
        
        # Initialize database
        self.init_db()
        
        # Start with login window
        self.show_login()
        
    def init_db(self):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                site TEXT,
                username TEXT,
                password TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # Check if user_id column exists, if not add it
        c.execute("PRAGMA table_info(passwords)")
        columns = [column[1] for column in c.fetchall()]
        if 'user_id' not in columns:
            c.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")
        
        conn.commit()
        conn.close()
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login(self):
        self.clear_window()
        self.root.title("Login - Password Manager")
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="50")
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = ttk.Label(main_frame, text="Login to Password Manager", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:").pack(pady=(0, 5))
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.pack(pady=(0, 15))
        
        # Password
        ttk.Label(main_frame, text="Password:").pack(pady=(0, 5))
        self.password_entry = ttk.Entry(main_frame, width=30, show="*")
        self.password_entry.pack(pady=(0, 20))
        
        # Login button
        login_btn = ttk.Button(main_frame, text="Login", command=self.login)
        login_btn.pack(pady=(0, 15))
        
        # Signup link
        signup_btn = ttk.Button(main_frame, text="Don't have an account? Sign up", 
                               command=self.show_signup)
        signup_btn.pack()
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.login())
    
    def show_signup(self):
        self.clear_window()
        self.root.title("Sign Up - Password Manager")
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="50")
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = ttk.Label(main_frame, text="Create Account", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 30))
        
        # Username
        ttk.Label(main_frame, text="Username:").pack(pady=(0, 5))
        self.signup_username_entry = ttk.Entry(main_frame, width=30)
        self.signup_username_entry.pack(pady=(0, 15))
        
        # Password
        ttk.Label(main_frame, text="Password:").pack(pady=(0, 5))
        self.signup_password_entry = ttk.Entry(main_frame, width=30, show="*")
        self.signup_password_entry.pack(pady=(0, 20))
        
        # Signup button
        signup_btn = ttk.Button(main_frame, text="Sign Up", command=self.signup)
        signup_btn.pack(pady=(0, 15))
        
        # Login link
        login_btn = ttk.Button(main_frame, text="Already have an account? Login", 
                              command=self.show_login)
        login_btn.pack()
        
        # Bind Enter key to signup
        self.root.bind('<Return>', lambda e: self.signup())
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode(), user[2]):
            self.current_user = {'id': user[0], 'username': user[1]}
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid credentials")
    
    def signup(self):
        username = self.signup_username_entry.get()
        password = self.signup_password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     (username, hashed_password))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_login()
        except sqlite3.IntegrityError:
            conn.close()
            messagebox.showerror("Error", "Username already taken")
    
    def show_dashboard(self):
        self.clear_window()
        self.root.title("Dashboard - Password Manager")
        
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(header_frame, text="Password Dashboard", 
                 font=('Arial', 16, 'bold')).pack(side='left')
        ttk.Button(header_frame, text="Logout", command=self.logout).pack(side='right')
        
        # Add password section
        add_frame = ttk.LabelFrame(self.root, text="Add New Password", padding="10")
        add_frame.pack(fill='x', padx=10, pady=5)
        
        # Add password form
        form_frame = ttk.Frame(add_frame)
        form_frame.pack(fill='x')
        
        ttk.Label(form_frame, text="Website:").grid(row=0, column=0, sticky='w', pady=2)
        self.site_entry = ttk.Entry(form_frame, width=25)
        self.site_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=2, sticky='w', pady=2)
        self.username_new_entry = ttk.Entry(form_frame, width=25)
        self.username_new_entry.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky='w', pady=2)
        self.password_new_entry = ttk.Entry(form_frame, width=25, show="*")
        self.password_new_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Button(form_frame, text="Save Password", command=self.add_password).grid(row=1, column=2, padx=5, pady=2)
        
        # Passwords list section
        list_frame = ttk.LabelFrame(self.root, text="Saved Passwords", padding="10")
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview for passwords
        columns = ('Website', 'Username', 'Password', 'Actions')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.root)
        buttons_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Copy Username", command=self.copy_username).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="Copy Password", command=self.copy_password).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="Show/Hide Password", command=self.toggle_password).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="Delete Selected", command=self.delete_password).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="Refresh", command=self.refresh_passwords).pack(side='left', padx=5)
        
        # Load passwords
        self.refresh_passwords()
        
        # Bind double-click to show password
        self.tree.bind('<Double-1>', lambda e: self.toggle_password())
    
    def add_password(self):
        site = self.site_entry.get()
        username = self.username_new_entry.get()
        password = self.password_new_entry.get()
        
        if not site or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("INSERT INTO passwords (user_id, site, username, password) VALUES (?, ?, ?, ?)",
                  (self.current_user['id'], site, username, encrypted_password))
        conn.commit()
        conn.close()
        
        # Clear form
        self.site_entry.delete(0, tk.END)
        self.username_new_entry.delete(0, tk.END)
        self.password_new_entry.delete(0, tk.END)
        
        # Refresh the list
        self.refresh_passwords()
        messagebox.showinfo("Success", "Password saved successfully!")
    
    def refresh_passwords(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Fetch passwords from database
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT id, site, username, password FROM passwords WHERE user_id = ?", 
                  (self.current_user['id'],))
        data = c.fetchall()
        conn.close()
        
        # Add passwords to tree
        for row in data:
            try:
                decrypted_password = self.fernet.decrypt(row[3].encode()).decode()
                # Store original password but show asterisks
                self.tree.insert('', 'end', values=(row[1], row[2], '••••••••', 'Actions'), 
                               tags=(row[0], decrypted_password))
            except Exception as e:
                self.tree.insert('', 'end', values=(row[1], row[2], 'Error', 'Actions'), 
                               tags=(row[0], 'Error'))
    
    def get_selected_item(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password entry")
            return None
        return selection[0]
    
    def copy_username(self):
        item = self.get_selected_item()
        if item:
            username = self.tree.item(item)['values'][1]
            pyperclip.copy(username)
            messagebox.showinfo("Success", "Username copied to clipboard!")
    
    def copy_password(self):
        item = self.get_selected_item()
        if item:
            password = self.tree.item(item)['tags'][1]
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def toggle_password(self):
        item = self.get_selected_item()
        if item:
            values = list(self.tree.item(item)['values'])
            if values[2] == '••••••••':
                values[2] = self.tree.item(item)['tags'][1]
            else:
                values[2] = '••••••••'
            self.tree.item(item, values=values)
    
    def delete_password(self):
        item = self.get_selected_item()
        if item:
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
                password_id = self.tree.item(item)['tags'][0]
                conn = sqlite3.connect('passwords.db')
                c = conn.cursor()
                c.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", 
                          (password_id, self.current_user['id']))
                conn.commit()
                conn.close()
                self.refresh_passwords()
                messagebox.showinfo("Success", "Password deleted successfully!")
    
    def logout(self):
        self.current_user = None
        self.show_login()
    
    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    app = PasswordManagerApp()
    app.run()
