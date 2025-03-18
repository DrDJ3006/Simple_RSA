# RSA Encryption Tool

This is a simple GUI-based RSA encryption and decryption tool built with Python and Tkinter. It allows users to generate RSA key pairs, encrypt messages using a public key, and decrypt messages using a private key.

## Features

- Generates RSA key pairs (2048-bit) and stores them on the desktop.
- Displays the public key in a separate window.
- Encrypts messages using the public key.
- Decrypts messages using the private key.
- Simple and user-friendly GUI.

## Requirements

For **Python users**, you need:

- Python 3.x
- The following Python libraries:
  - `tkinter` (built-in with Python)
  - `cryptography` (install using `pip`)

For **Windows users running the executable**:  
No dependencies are required.

## Installation

### **Running from Python Source Code**
1. Clone or download this repository.
2. Install dependencies if needed:

   ```sh
   pip install cryptography
   ```

3. Run the script:

   ```sh
   python main.py
   ```

### **Running the Compiled Executable (`simple-rsa.exe`)**
1. Download `simple-rsa.exe` (or compile it using `auto-py-to-exe`).
2. Double-click `simple-rsa.exe` to start the application.

## Usage

1. **Generating Keys:** The script automatically generates an RSA key pair (`private_key.pem` and `public_key.pem`) in a folder named `Simple_RSA` on your desktop.
2. **Exporting Public Key:** Click the "Export Key" button to display the public key.
3. **Encrypting a Message:**
   - Click "Encrypt".
   - Enter a message and press "Encrypt".
   - The encrypted message (hex format) will be displayed in a pop-up.
4. **Decrypting a Message:**
   - Click "Decrypt".
   - Paste an encrypted message (hex format) and press "Decrypt".
   - If the correct private key is used, the decrypted message will be shown.

## Security Considerations

- **Private Key Protection:** The private key should not be shared. It is stored in `Simple_RSA/private_key.pem` on your desktop.
- **No Password Protection:** Currently, the private key is not encrypted with a passphrase.
- **Encryption Strength:** Uses RSA-2048 with OAEP padding (SHA-256) for strong security.

## Compiling to an Executable (Optional)

To create an executable from the Python script:

1. Install `auto-py-to-exe`:

   ```sh
   pip install auto-py-to-exe
   ```

2. Run `auto-py-to-exe`:

   ```sh
   auto-py-to-exe
   ```

3. Select **"One Directory"** or **"One File"**, then click **"Convert"**.

4. The generated `main.exe` will be found inside the `dist` folder.

## License

This project is open-source under the MIT License.
