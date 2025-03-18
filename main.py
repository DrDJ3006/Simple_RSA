import os
import tkinter as tk
from tkinter import messagebox, Toplevel, Scrollbar, Button
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Constantes pour les chemins de fichier et la configuration de la fenêtre
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

def get_desktop_path():
    """Retourne le chemin du bureau pour l'utilisateur actuel."""
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['USERPROFILE'], 'Desktop')
    else:  # MacOS, Linux
        return os.path.join(os.path.expanduser('~'), 'Desktop')

def setup_application():
    desktop_path = get_desktop_path()
    app_folder = os.path.join(desktop_path, 'Simple_RSA')
    if not os.path.exists(app_folder):
        os.makedirs(app_folder)
    return app_folder

def generate_keys(app_folder):
    """Génère et sauvegarde les clés RSA privée et publique dans le dossier spécifié."""
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_path = os.path.join(app_folder, 'private_key.pem')
    public_key_path = os.path.join(app_folder, 'public_key.pem')

    with open(private_key_path, 'wb') as f:
        f.write(pem_private)
    with open(public_key_path, 'wb') as f:
        f.write(pem_public)

    return private_key_path, public_key_path

def load_private_key(private_key_path):
    """Charge la clé privée depuis un fichier."""
    with open(private_key_path, 'rb') as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=None
        )

def load_public_key(public_key_path):
    """Charge la clé publique depuis un fichier."""
    with open(public_key_path, 'rb') as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=None
        )

def show_public_key():
    """Affiche la clé publique dans une nouvelle fenêtre."""
    top = Toplevel(root)
    top.title("Clé Publique RSA")
    center_window(top, 550, 300)

    text = tk.Text(top, wrap='word')
    scroll = Scrollbar(top, command=text.yview)
    text.configure(yscrollcommand=scroll.set)
    public_key_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    text.insert('1.0', public_key_pem)
    text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    text.configure(state='disabled')

def encrypt_message():
    """Chiffre un message en utilisant la clé publique chargée."""
    encryption_window = Toplevel(root)
    encryption_window.title("Chiffrer un message")
    center_window(encryption_window, 400, 300)

    tk.Label(encryption_window, text="Entrez le message à chiffrer:").pack(pady=(10, 0))
    message_text = tk.Text(encryption_window, height=5, width=50)
    message_text.pack(pady=10)

    def perform_encryption():
        message = message_text.get("1.0", "end").strip()
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        messagebox.showinfo("Message chiffré", encrypted.hex())

    tk.Button(encryption_window, text="Chiffrer", command=perform_encryption).pack(pady=10)

def decrypt_message():
    """Déchiffre un message en utilisant la clé privée chargée."""
    decryption_window = Toplevel(root)
    decryption_window.title("Déchiffrer un message")
    center_window(decryption_window, 400, 300)

    tk.Label(decryption_window, text="Entrez le message chiffré (en hexadécimal):").pack(pady=(10, 0))
    encrypted_text = tk.Text(decryption_window, height=5, width=50)
    encrypted_text.pack(pady=10)

    def perform_decryption():
        encrypted_message_hex = encrypted_text.get("1.0", "end").strip()
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        try:
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            messagebox.showinfo("Message déchiffré", decrypted_message.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Erreur de déchiffrement", str(e))

    tk.Button(decryption_window, text="Déchiffrer", command=perform_decryption).pack(pady=10)

def center_window(win, width, height):
    """Centre la fenêtre sur l'écran."""
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    win.geometry(f'{width}x{height}+{x}+{y}')

app_folder = setup_application()
private_key_path, public_key_path = generate_keys(app_folder)
private_key = load_private_key(private_key_path)
public_key = load_public_key(public_key_path)

root = tk.Tk()
root.title("Outils de Cryptographie")
center_window(root, 300, 150)

export_button = tk.Button(root, text="Exporter clé", command=show_public_key)
export_button.pack(pady=5)
encrypt_button = tk.Button(root, text="Chiffrer", command=encrypt_message)
encrypt_button.pack(pady=5)
decrypt_button = tk.Button(root, text="Déchiffrer", command=decrypt_message)
decrypt_button.pack(pady=5)

root.mainloop()
