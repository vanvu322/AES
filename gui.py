import tkinter as tk
from tkinter import messagebox
from encryption import AES128, AES192, AES256
from aesUtils import stringToState, stateToString

def encrypt_data():
    plain_text = entry_plain_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    aes_type = var_aes.get()
    
    if not plain_text or not key:
        messagebox.showwarning("Input Error", "Please enter both plain text and key.")
        return
    
    # Convert plain text to 4x4 state matrix
    state = stringToState(plain_text)
    if aes_type == "AES-128":
        cipher_state = AES128(state, key)
    elif aes_type == "AES-192":
        cipher_state = AES192(state, key)
    elif aes_type == "AES-256":
        cipher_state = AES256(state, key)
    
    cipher_text = stateToString(cipher_state)
    entry_cipher_text.delete("1.0", tk.END)
    entry_cipher_text.insert(tk.END, cipher_text)

# Initialize main window
root = tk.Tk()
root.title("AES Encryption")

# Plain Text
label_plain_text = tk.Label(root, text="Plain Text:")
label_plain_text.grid(row=0, column=0, padx=5, pady=5)
entry_plain_text = tk.Text(root, height=10, width=50)
entry_plain_text.grid(row=0, column=1, padx=5, pady=5)

# Key
label_key = tk.Label(root, text="Key:")
label_key.grid(row=1, column=0, padx=5, pady=5)
entry_key = tk.Entry(root, width=50)
entry_key.grid(row=1, column=1, padx=5, pady=5)

# AES Type
label_aes = tk.Label(root, text="AES Type:")
label_aes.grid(row=2, column=0, padx=5, pady=5)
var_aes = tk.StringVar(value="AES-128")
aes_options = ["AES-128", "AES-192", "AES-256"]
drop_aes = tk.OptionMenu(root, var_aes, *aes_options)
drop_aes.grid(row=2, column=1, padx=5, pady=5)

# Encrypt Button
button_encrypt = tk.Button(root, text="Encrypt", command=encrypt_data)
button_encrypt.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Cipher Text
label_cipher_text = tk.Label(root, text="Cipher Text:")
label_cipher_text.grid(row=4, column=0, padx=5, pady=5)
entry_cipher_text = tk.Text(root, height=10, width=50)
entry_cipher_text.grid(row=4, column=1, padx=5, pady=5)

# Start main loop
root.mainloop()
