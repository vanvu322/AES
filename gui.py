import tkinter as tk
from tkinter import messagebox
from aesUtils import *
import encryption as en
import decryption as de
import numpy as np

def encrypt_helper(state=None, key=None, b64=False, mode="ECB", IV=None, hexain=False, hexakey=False, hexaIV=False, hexaout=False):
    ret = ""
    lenkey = 0

    b64 = True if b64 == "True" else b64
    hexain = True if hexain == "True" else hexain
    hexakey = True if hexakey == "True" else hexakey
    hexaIV = True if hexaIV == "True" else hexaIV
    hexaout = True if hexaout == "True" else hexaout

    if hexakey:
        lenkey = len(key) // 2
    else:
        lenkey = len(key)

    if b64:
        state = b64e(state)

    func = {
        16: en.AES128,
        24: en.AES192,
        32: en.AES256
    }

    matConversion = {
        True: matToHexa,
        False: matToString
    }

    strConversion = {
        False: stringToMat,
        True: hexaToMat
    }

    if hexain:
        res = [state[y - 32:y] for y in range(32, len(state) + 32, 32)]
        lim = 32 - len(res[-1])
    else:
        res = [state[y - 16:y] for y in range(16, len(state) + 16, 16)]
        lim = 16 - len(res[-1])

    for i in range(0, lim):
        res[-1] += chr(0x00)

    key = strConversion[hexakey](key)
    if lenkey != 16:
        cypherkey = np.transpose(key)
        cypherkey = cypherkey.tolist()
    else:
        cypherkey = key

    if mode == "CBC":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            sub = xorMatrix(sub, temp)
            sub = func[lenkey](sub, cypherkey)
            temp = sub
            sub = matConversion[hexaout](sub)
            ret += sub

    elif mode == "CFB":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            temp = func[lenkey](temp, cypherkey)
            sub = xorMatrix(sub, temp)
            temp = sub
            sub = matConversion[hexaout](sub)
            ret += sub

    elif mode == "OFB":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            temp = func[lenkey](temp, cypherkey)
            sub = xorMatrix(sub, temp)
            sub = matConversion[hexaout](sub)
            ret += sub

    else:
        for i in res:
            sub = strConversion[hexain](i)
            sub = func[lenkey](sub, cypherkey)
            sub = matConversion[hexaout](sub)
            ret += sub

    return ret


def decrypt_helper(state=None, key=None, b64=False, mode="ECB", IV=None, hexain=False, hexakey=False, hexaIV=False, hexaout=False):
    ret = ""
    lenkey = 0

    b64 = True if b64 == "True" else b64
    hexain = True if hexain == "True" else hexain
    hexakey = True if hexakey == "True" else hexakey
    hexaIV = True if hexaIV == "True" else hexaIV
    hexaout = True if hexaout == "True" else hexaout

    if hexakey:
        lenkey = len(key) // 2
    else:
        lenkey = len(key)

    func = {
        16: de.AES128,
        24: de.AES192,
        32: de.AES256
    }

    enfunc = {
        16: en.AES128,
        24: en.AES192,
        32: en.AES256
    }

    matConversion = {
        True: matToHexa,
        False: matToString
    }

    strConversion = {
        False: stringToMat,
        True: hexaToMat
    }

    if hexain:
        res = [state[y - 32:y] for y in range(32, len(state) + 32, 32)]
        lim = 32 - len(res[-1])
    else:
        res = [state[y - 16:y] for y in range(16, len(state) + 16, 16)]
        lim = 16 - len(res[-1])

    for i in range(0, lim):
        res[-1] += chr(0x00)

    key = strConversion[hexakey](key)
    if lenkey != 16:
        cypherkey = np.transpose(key)
        cypherkey = cypherkey.tolist()
    else:
        cypherkey = key

    if mode == "CBC":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            sub = func[lenkey](sub, cypherkey)
            sub = xorMatrix(sub, temp)
            sub = matConversion[hexaout](sub)
            temp = strConversion[hexain](i)
            ret += sub

    elif mode == "CFB":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            temp = enfunc[lenkey](temp, cypherkey)
            sub = xorMatrix(sub, temp)
            temp = strConversion[hexain](i)
            sub = matConversion[hexaout](sub)
            ret += sub

    elif mode == "OFB":
        temp = strConversion[hexaIV](IV)
        for i in res:
            sub = strConversion[hexain](i)
            temp = enfunc[lenkey](temp, cypherkey)
            sub = xorMatrix(sub, temp)
            sub = matConversion[hexaout](sub)
            ret += sub

    else:
        for i in res:
            sub = strConversion[hexain](i)
            sub = func[lenkey](sub, cypherkey)
            sub = matConversion[hexaout](sub)
            ret += sub

    ret = ret.rstrip(chr(0x00))

    if b64:
        ret = b64d(ret)

    return ret


# Tkinter GUI implementation

def encrypt():
    state = state_entry.get()
    key = key_entry.get()
    IV = iv_entry.get() if iv_entry.winfo_ismapped() else None
    mode = mode_var.get()
    b64 = b64_var.get()
    hexain = hexain_var.get()
    hexakey = hexakey_var.get()
    hexaIV = hexaIV_var.get()
    hexaout = hexaout_var.get()

    if not state or not key:
        messagebox.showerror("Error", "State and key are required")
        return

    cipher = encrypt_helper(state, key, b64, mode, IV, hexain, hexakey, hexaIV, hexaout)
    cipher_output.delete(0, tk.END)
    cipher_output.insert(0, cipher)

def decrypt():
    state = state_entry.get()
    key = key_entry.get()
    IV = iv_entry.get() if iv_entry.winfo_ismapped() else None
    mode = mode_var.get()
    b64 = b64_var.get()
    hexain = hexain_var.get()
    hexakey = hexakey_var.get()
    hexaIV = hexaIV_var.get()
    hexaout = hexaout_var.get()

    if not state or not key:
        messagebox.showerror("Error", "State and key are required")
        return

    plain = decrypt_helper(state, key, b64, mode, IV, hexain, hexakey, hexaIV, hexaout)
    cipher_output.delete(0, tk.END)
    cipher_output.insert(0, plain)

def toggle_iv_visibility():
    if mode_var.get() == "ECB":
        iv_label.grid_remove()
        iv_entry.grid_remove()
        hexIV_check.grid_remove()
    else:
        iv_label.grid()
        iv_entry.grid()
        hexIV_check.grid()

root = tk.Tk()
root.title("AES Encryption/Decryption")

tk.Label(root, text="Input").grid(row=0, column=0)
state_entry = tk.Entry(root, width=50)
state_entry.grid(row=0, column=1, columnspan=2)

tk.Label(root, text="Cipherkey").grid(row=1, column=0)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=1, column=1, columnspan=2)

iv_label = tk.Label(root, text="Initialize Vector")
iv_label.grid(row=2, column=0)
iv_entry = tk.Entry(root, width=50)
iv_entry.grid(row=2, column=1, columnspan=2)

tk.Label(root, text="Output").grid(row=3, column=0)
cipher_output = tk.Entry(root, width=50)
cipher_output.grid(row=3, column=1, columnspan=2)

hexain_var = tk.BooleanVar()
tk.Checkbutton(root, text="Input as hex string", variable=hexain_var).grid(row=4, column=0)

hexakey_var = tk.BooleanVar()
tk.Checkbutton(root, text="Key as hex string", variable=hexakey_var).grid(row=4, column=1)

hexaIV_var = tk.BooleanVar()
hexIV_check = tk.Checkbutton(root, text="IV as hex string", variable=hexaIV_var)
hexIV_check.grid(row=5, column=0)

hexaout_var = tk.BooleanVar()
tk.Checkbutton(root, text="Output as hex string", variable=hexaout_var).grid(row=4, column=2)

b64_var = tk.BooleanVar()
tk.Checkbutton(root, text="Uses base64", variable=b64_var).grid(row=5, column=1)

mode_var = tk.StringVar(value="ECB")
tk.Radiobutton(root, text="ECB", variable=mode_var, value="ECB", command=toggle_iv_visibility).grid(row=6, column=0)
tk.Radiobutton(root, text="CBC", variable=mode_var, value="CBC", command=toggle_iv_visibility).grid(row=6, column=1)
tk.Radiobutton(root, text="CFB", variable=mode_var, value="CFB", command=toggle_iv_visibility).grid(row=6, column=2)
tk.Radiobutton(root, text="OFB", variable=mode_var, value="OFB", command=toggle_iv_visibility).grid(row=6, column=3)

tk.Button(root, text="Encrypt", command=encrypt).grid(row=7, column=1)
tk.Button(root, text="Decrypt", command=decrypt).grid(row=7, column=2)

toggle_iv_visibility()  # Set initial visibility of IV components
root.mainloop()
