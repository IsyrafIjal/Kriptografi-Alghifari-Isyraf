import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
import base64
import os

selected_file = None  # Menyimpan file yang dipilih


def select_file():
    """Memilih file dari sistem"""
    global selected_file
    selected_file = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, selected_file)


def save_file(content, encrypt=True, original_ext=""):
    """Menyimpan hasil enkripsi/dekripsi ke file"""
    default_extension = ".enc" if encrypt else original_ext
    file_path = filedialog.asksaveasfilename(defaultextension=default_extension, filetypes=[("All Files", "*.*")])
    
    if file_path:
        with open(file_path, "wb") as file:
            file.write(content)
        messagebox.showinfo("Sukses", f"File disimpan di: {file_path}")


def read_file():
    """Membaca isi file sebagai bytes"""
    global selected_file
    if selected_file:
        with open(selected_file, "rb") as file:
            return file.read()
    return None


# ==================== ALGORITMA ENKRIPSI ====================

def xor_encrypt_decrypt(data, key):
    key_bytes = key.encode()
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])


def rc4_encrypt_decrypt(data, key):
    S = list(range(256))
    j = 0
    out = bytearray()
    key = key.encode()
    key = [key[i % len(key)] for i in range(256)]
    
    for i in range(256):
        j = (j + S[i] + key[i]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    
    return bytes(out)


def des_encrypt_decrypt(data, key, mode, encrypt=True):
    key = key.ljust(8, ' ')[:8].encode()
    iv = b'12345678'
    if mode == DES.MODE_CBC:
        cipher = DES.new(key, mode, iv)
    elif mode == DES.MODE_CTR:
        ctr = Counter.new(64)
        cipher = DES.new(key, mode, counter=ctr)
    else:
        cipher = DES.new(key, mode)

    if encrypt:
        return cipher.encrypt(pad(data, DES.block_size))
    else:
        return unpad(cipher.decrypt(data), DES.block_size)


def aes_encrypt_decrypt(data, key, mode, encrypt=True):
    key = key.ljust(16, ' ')[:16].encode()
    iv = b'1234567812345678'
    if mode == AES.MODE_CBC:
        cipher = AES.new(key, mode, iv)
    elif mode == AES.MODE_CTR:
        ctr = Counter.new(128)
        cipher = AES.new(key, mode, counter=ctr)
    else:
        cipher = AES.new(key, mode)

    if encrypt:
        return cipher.encrypt(pad(data, AES.block_size))
    else:
        return unpad(cipher.decrypt(data, AES.block_size))
def xor_encrypt(text, key):
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

def xor_decrypt(text, key):
    return xor_encrypt(text, key)  # XOR dekripsi sama dengan enkripsi

# Fungsi RC4
def rc4_crypt(text, key):
    S = list(range(256))
    j = 0
    out = []
    
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    for char in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    
    return "".join(out)

# Fungsi DES
def des_encrypt(text, key, mode):
    key = key[:8].ljust(8, '\0').encode()  # Panjang kunci harus 8 byte
    cipher = DES.new(key, mode)
    if mode == DES.MODE_ECB:
        encrypted = cipher.encrypt(pad(text.encode(), DES.block_size))
    else:
        iv = os.urandom(8)  # Inisialisasi vektor
        cipher = DES.new(key, mode, iv)
        encrypted = iv + cipher.encrypt(pad(text.encode(), DES.block_size))
    return base64.b64encode(encrypted).decode()

def des_decrypt(text, key, mode):
    key = key[:8].ljust(8, '\0').encode()
    raw_data = base64.b64decode(text)
    if mode == DES.MODE_ECB:
        cipher = DES.new(key, mode)
        decrypted = unpad(cipher.decrypt(raw_data), DES.block_size)
    else:
        iv, data = raw_data[:8], raw_data[8:]
        cipher = DES.new(key, mode, iv)
        decrypted = unpad(cipher.decrypt(data), DES.block_size)
    return decrypted.decode()

# Fungsi AES
def aes_encrypt(text, key, mode):
    key = key[:16].ljust(16, '\0').encode()  # Panjang kunci harus 16 byte
    cipher = AES.new(key, mode)
    if mode == AES.MODE_ECB:
        encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    else:
        iv = os.urandom(16)
        cipher = AES.new(key, mode, iv)
        encrypted = iv + cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(text, key, mode):
    key = key[:16].ljust(16, '\0').encode()
    raw_data = base64.b64decode(text)
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
        decrypted = unpad(cipher.decrypt(raw_data), AES.block_size)
    else:
        iv, data = raw_data[:16], raw_data[16:]
        cipher = AES.new(key, mode, iv)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted.decode()

# ==================== FUNGSI UI ====================

def process_encryption():
    global selected_file
    data = read_file()
    key = entry_key_encrypt.get().strip()
    method = encryption_method.get()

    if not data or not key:
        messagebox.showerror("Error", "Masukkan file dan kunci!")
        return

    try:
        if method == "Simple XOR":
            result = xor_encrypt_decrypt(data, key)
        elif method == "RC4":
            result = rc4_encrypt_decrypt(data, key)
        elif method.startswith("DES"):
            mode = DES.MODE_ECB if "ECB" in method else DES.MODE_CBC if "CBC" in method else DES.MODE_CTR
            result = des_encrypt_decrypt(data, key, mode)
        elif method.startswith("AES"):
            mode = AES.MODE_ECB if "ECB" in method else AES.MODE_CBC if "CBC" in method else AES.MODE_CTR
            result = aes_encrypt_decrypt(data, key, mode)

        # Simpan file dengan ekstensi asli sebagai metadata
        ext = os.path.splitext(selected_file)[1]  # Ambil ekstensi file asli
        save_file(ext.encode() + b"\n" + result, encrypt=True)

    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")


def process_decryption():
    global selected_file
    data = read_file()
    key = entry_key_decrypt.get().strip()
    method = decryption_method.get()

    if not data or not key:
        messagebox.showerror("Error", "Masukkan file dan kunci!")
        return

    try:
        # Ambil ekstensi file asli dari metadata
        first_newline = data.find(b"\n")
        if first_newline == -1:
            messagebox.showerror("Error", "File terenkripsi tidak memiliki metadata!")
            return

        original_ext = data[:first_newline].decode()
        encrypted_data = data[first_newline + 1:]

        if method == "Simple XOR":
            result = xor_encrypt_decrypt(encrypted_data, key)
        elif method == "RC4":
            result = rc4_encrypt_decrypt(encrypted_data, key)
        elif method.startswith("DES"):
            mode = DES.MODE_ECB if "ECB" in method else DES.MODE_CBC if "CBC" in method else DES.MODE_CTR
            result = des_encrypt_decrypt(encrypted_data, key, mode, encrypt=False)
        elif method.startswith("AES"):
            mode = AES.MODE_ECB if "ECB" in method else AES.MODE_CBC if "CBC" in method else AES.MODE_CTR
            result = aes_encrypt_decrypt(encrypted_data, key, mode, encrypt=False)

        save_file(result, encrypt=False, original_ext=original_ext)

    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")
def process():
    text = entry_text.get("1.0", tk.END).strip()
    key = entry_key.get().strip()
    mode = algo_var.get()
    action = action_var.get()
    
    if not text or not key:
        messagebox.showerror("Error", "Teks dan Kunci tidak boleh kosong!")
        return
    
    try:
        if mode == "XOR":
            result = xor_encrypt(text, key) if action == "Encrypt" else xor_decrypt(text, key)
        elif mode == "RC4":
            result = rc4_crypt(text, key)
        elif mode == "DES-ECB":
            result = des_encrypt(text, key, DES.MODE_ECB) if action == "Encrypt" else des_decrypt(text, key, DES.MODE_ECB)
        elif mode == "DES-CBC":
            result = des_encrypt(text, key, DES.MODE_CBC) if action == "Encrypt" else des_decrypt(text, key, DES.MODE_CBC)
        elif mode == "AES-ECB":
            result = aes_encrypt(text, key, AES.MODE_ECB) if action == "Encrypt" else aes_decrypt(text, key, AES.MODE_ECB)
        elif mode == "AES-CBC":
            result = aes_encrypt(text, key, AES.MODE_CBC) if action == "Encrypt" else aes_decrypt(text, key, AES.MODE_CBC)
        else:
            result = "Mode tidak valid!"
        
        entry_result.delete("1.0", tk.END)
        entry_result.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Terjadi kesalahan: {e}")
# ==================== SETUP UI ====================

root = tk.Tk()
root.title("Aplikasi Enkripsi & Dekripsi File")

notebook = ttk.Notebook(root)

frame_encrypt = ttk.Frame(notebook)
frame_decrypt = ttk.Frame(notebook)

notebook.add(frame_encrypt, text="Enkripsi File")
notebook.add(frame_decrypt, text="Dekripsi File")
notebook.pack(expand=True, fill="both")

# ENKRIPSI
ttk.Label(frame_encrypt, text="Pilih File:").pack()
entry_file_path = tk.Entry(frame_encrypt, width=50)
entry_file_path.pack()
ttk.Button(frame_encrypt, text="Browse", command=select_file).pack()

ttk.Label(frame_encrypt, text="Masukkan Kunci:").pack()
entry_key_encrypt = tk.Entry(frame_encrypt)
entry_key_encrypt.pack()

encryption_method = ttk.Combobox(frame_encrypt, values=[
    "Simple XOR", "RC4", "DES (ECB)", "DES (CBC)", "DES (CTR)", "AES (ECB)", "AES (CBC)", "AES (CTR)"])
encryption_method.pack()

ttk.Button(frame_encrypt, text="Enkripsi", command=process_encryption).pack()

root = tk.Tk()
root.title("Encrypt & Decrypt Tool")

frame = ttk.Frame(root, padding=10)
frame.grid(row=0, column=0, sticky="EW")

ttk.Label(frame, text="Teks:").grid(row=0, column=0, sticky="W")
entry_text = tk.Text(frame, width=40, height=4)
entry_text.grid(row=1, column=0, columnspan=2)

ttk.Label(frame, text="Kunci:").grid(row=2, column=0, sticky="W")
entry_key = ttk.Entry(frame, width=40)
entry_key.grid(row=3, column=0, columnspan=2)

ttk.Label(frame, text="Algoritma:").grid(row=4, column=0, sticky="W")
algo_var = ttk.Combobox(frame, values=["XOR", "RC4", "DES-ECB", "DES-CBC", "AES-ECB", "AES-CBC"])
algo_var.grid(row=5, column=0, columnspan=2)
algo_var.current(0)

ttk.Label(frame, text="Aksi:").grid(row=6, column=0, sticky="W")
action_var = ttk.Combobox(frame, values=["Encrypt", "Decrypt"])
action_var.grid(row=7, column=0, columnspan=2)
action_var.current(0)

btn_process = ttk.Button(frame, text="Proses", command=process)
btn_process.grid(row=8, column=0, columnspan=2)

ttk.Label(frame, text="Hasil:").grid(row=9, column=0, sticky="W")
entry_result = tk.Text(frame, width=40, height=4)
entry_result.grid(row=10, column=0, columnspan=2)

root.mainloop()

# DEKRIPSI
ttk.Label(frame_decrypt, text="Pilih File:").pack()
entry_file_path_decrypt = tk.Entry(frame_decrypt, width=50)
entry_file_path_decrypt.pack()
ttk.Button(frame_decrypt, text="Browse", command=select_file).pack()

ttk.Label(frame_decrypt, text="Masukkan Kunci:").pack()
entry_key_decrypt = tk.Entry(frame_decrypt)
entry_key_decrypt.pack()

decryption_method = ttk.Combobox(frame_decrypt, values=encryption_method["values"])
decryption_method.pack()

ttk.Button(frame_decrypt, text="Dekripsi", command=process_decryption).pack()

root.mainloop()
