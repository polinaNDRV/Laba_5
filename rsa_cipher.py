import tkinter as tk
from tkinter import messagebox
import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def is_prime(n):
    """Проверка, является ли число простым."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_large_prime(bits):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

def generate_keypair():
    p = generate_large_prime(16)
    q = generate_large_prime(16)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Выбор e
    e = 65537
    if gcd(e, phi) != 1: # убежддаемся, что они простые
        raise ValueError("Выберите другие p и q.")

    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

def decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext

def generate_keys():
    public_key, private_key = generate_keypair()

    public_key_entry.delete(0, tk.END)
    public_key_entry.insert(0, str(public_key))
    root.private_key = private_key
def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    public_key = eval(public_key_entry.get())
    if not plaintext:
        messagebox.showerror("Ошибка", "Введите текст для шифрования.")
        return
    ciphertext = encrypt(public_key, plaintext)
    encrypted_text_entry.delete("1.0", tk.END)
    encrypted_text_entry.insert(tk.END, ' '.join(map(str, ciphertext)))

def decrypt_text():
    ciphertext_str = encrypted_text_entry.get("1.0", tk.END).strip()

    if not ciphertext_str:
        messagebox.showerror("Ошибка", "Введите текст для дешифрования.")
        return

    ciphertext = list(map(int, ciphertext_str.split()))
    private_key = root.private_key
    plaintext = decrypt(private_key, ciphertext)
    decrypted_text_entry.delete("1.0", tk.END)
    decrypted_text_entry.insert(tk.END, plaintext)

# Интерфейс
root = tk.Tk()
root.title("RSA")

plaintext_label = tk.Label(root, text="Исходный текст:")
plaintext_label.pack()
plaintext_entry = tk.Text(root, height=5, width=50)
plaintext_entry.pack()

generate_keys_button = tk.Button(root, text="Сгенерировать ключ", command=generate_keys)
generate_keys_button.pack()

public_key_label = tk.Label(root, text="Публичный ключ:")
public_key_label.pack()
public_key_entry = tk.Entry(root, width=50)
public_key_entry.pack()

encrypt_button = tk.Button(root, text="Зашифровать", command=encrypt_text)
encrypt_button.pack()

encrypted_text_label = tk.Label(root, text="Зашифрованный текст:")
encrypted_text_label.pack()
encrypted_text_entry = tk.Text(root, height=5, width=50)
encrypted_text_entry.pack()

decrypt_button = tk.Button(root, text="Дешифровать", command=decrypt_text)
decrypt_button.pack()

decrypted_text_label = tk.Label(root, text="Дешифрованный текст:")
decrypted_text_label.pack()
decrypted_text_entry = tk.Text(root, height=5, width=50)
decrypted_text_entry.pack()

root.mainloop()