from Crypto.Cipher import AES
from hashlib import sha256
import os

# === Reconstruct the encryption key ===
KEY_SUFFIX = "RahsiaLagi"
KEY_STR = f"Bukan{KEY_SUFFIX}"
KEY = sha256(KEY_STR.encode()).digest()[:16]

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_file(filepath):
    with open(filepath, "rb") as f:
        ciphertext = f.read()
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted)
    
    # Save decrypted file with new name
    output_path = filepath.replace(".txt.enc", ".dec.txt")
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted: {filepath} -> {output_path}")

if __name__ == "__main__":
    folder = "locked_files"
    files = os.listdir(folder)
    print("Files in locked_files:", files)
    
    for filename in files:
        if filename.endswith(".txt.enc"):
            full_path = os.path.join(folder, filename)
            print(f"Decrypting: {filename}")
            decrypt_file(full_path)

