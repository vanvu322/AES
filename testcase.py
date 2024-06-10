import tkinter as tk
from tkinter import ttk
import random
import string
from tkinter import messagebox

def generate_key(key_length):
    """Generate a random AES key."""
    if key_length == 128:
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    elif key_length == 192:
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    elif key_length == 256:
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return key

def generate_plaintext(length):
    """Generate random plaintext."""
    plaintext = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return plaintext

def generate_data():
    """Generate AES test data."""
    key_length = int(key_length_var.get())
    plaintext_length = int(plaintext_length_entry.get())
    num_samples = int(num_samples_entry.get())

    if num_samples <= 0 or plaintext_length <= 0 or key_length <= 0:
        messagebox.showerror("Error", "Invalid input values")
        return

    test_data = ""
    for _ in range(num_samples):
        key = generate_key(key_length)
        plaintext = generate_plaintext(plaintext_length)
        test_data += f"Plaintext: {plaintext}\nKey: {key}\n\n"

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, test_data)

root = tk.Tk()
root.title("AES Test Data Generator")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

key_length_label = ttk.Label(mainframe, text="AES Key Length (bits):")
key_length_label.grid(column=0, row=0, sticky=tk.W)
key_length_var = tk.StringVar()
key_length_combobox = ttk.Combobox(mainframe, textvariable=key_length_var, values=[128, 192, 256])
key_length_combobox.grid(column=1, row=0, sticky=tk.W)
key_length_combobox.current(0)

plaintext_length_label = ttk.Label(mainframe, text="Plaintext Length:")
plaintext_length_label.grid(column=0, row=1, sticky=tk.W)
plaintext_length_entry = ttk.Entry(mainframe)
plaintext_length_entry.grid(column=1, row=1, sticky=tk.W)

num_samples_label = ttk.Label(mainframe, text="Number of Samples:")
num_samples_label.grid(column=0, row=2, sticky=tk.W)
num_samples_entry = ttk.Entry(mainframe)
num_samples_entry.grid(column=1, row=2, sticky=tk.W)

generate_button = ttk.Button(mainframe, text="Generate Data", command=generate_data)
generate_button.grid(column=0, row=3, columnspan=2)

output_label = ttk.Label(mainframe, text="Generated Data:")
output_label.grid(column=0, row=4, sticky=tk.W)
output_text = tk.Text(mainframe, width=50, height=20)
output_text.grid(column=0, row=5, columnspan=2, sticky=(tk.W, tk.E))

root.mainloop()
