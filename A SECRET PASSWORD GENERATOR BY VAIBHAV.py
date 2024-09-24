import tkinter as tk
from tkinter import messagebox
import random
import string

# Function to generate password
def generate_password():
    length = int(length_entry.get())  # Get the length of the password
    include_uppercase = uppercase_var.get()  # Check if uppercase letters should be included
    include_numbers = numbers_var.get()  # Check if numbers should be included
    include_symbols = symbols_var.get()  # Check if symbols should be included

    # Define character sets
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase if include_uppercase else ''
    numbers = string.digits if include_numbers else ''
    symbols = string.punctuation if include_symbols else ''

    # Combine all chosen character sets
    all_chars = lower + upper + numbers + symbols

    if not all_chars:
        messagebox.showerror("Error", "Please select at least one character type.")
        return
    
    # Generate password
    password = ''.join(random.choice(all_chars) for _ in range(length))
    
    # Display the password
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

# Function to copy password to clipboard
def copy_password():
    password = password_entry.get()
    root.clipboard_clear()
    root.clipboard_append(password)
    messagebox.showinfo("Success", "Password copied to clipboard")

# Create the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("400x300")
root.resizable(False, False)

# Labels and Entry for password length
tk.Label(root, text="Password Length:").pack(pady=5)
length_entry = tk.Entry(root)
length_entry.pack()

# Checkboxes for password criteria
uppercase_var = tk.IntVar()
tk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var).pack(pady=5)

numbers_var = tk.IntVar()
tk.Checkbutton(root, text="Include Numbers", variable=numbers_var).pack(pady=5)

symbols_var = tk.IntVar()
tk.Checkbutton(root, text="Include Symbols", variable=symbols_var).pack(pady=5)

# Button to generate password
tk.Button(root, text="Generate Password", command=generate_password).pack(pady=10)

# Entry to display generated password
password_entry = tk.Entry(root, font=("Helvetica", 12), width=30)
password_entry.pack(pady=10)

# Button to copy password
tk.Button(root, text="Copy Password", command=copy_password).pack(pady=5)

# Run the application
root.mainloop()
