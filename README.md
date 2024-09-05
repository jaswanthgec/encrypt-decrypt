# encrypt-decrypt
15 different encryption and decryption algorithms

# Encryption/Decryption Tool using Streamlit

This project is an interactive web application built using **Streamlit** that allows users to encrypt and decrypt text using a variety of popular encryption algorithms. It provides a user-friendly interface where users can select from 15 different encryption and decryption algorithms, input their plaintext or ciphertext, and either encrypt or decrypt it based on their selection.

## Features

- **Supports multiple encryption and decryption algorithms**:
  - Symmetric Key Encryption:
    - AES (Advanced Encryption Standard)
    - DES (Data Encryption Standard)
    - 3DES (Triple DES)
    - Blowfish
    - ChaCha20
    - CAST5
    - RC2
  - Basic Cipher Algorithms:
    - Caesar Cipher
    - Atbash Cipher
    - XOR Cipher

- **Algorithm-Specific Key Information**: 
  - The app provides detailed information about the key requirements for each algorithm, ensuring users provide valid keys for encryption/decryption.
  
- **Real-Time Encryption/Decryption**:
  - Users receive immediate feedback for their encryption and decryption requests, along with error handling if the input data or keys are invalid.

- **Cybersecurity-Themed Design**:
  - The app features a modern dark theme and professional styling to create a polished, user-friendly experience.

## Technologies Used

- **Streamlit**: A Python-based framework for building interactive web applications.
- **PyCryptodome**: A cryptographic library used to handle encryption and decryption algorithms such as AES, DES, 3DES, Blowfish, and more.
- **Python**: Programming language used to implement basic ciphers like Caesar Cipher, Atbash Cipher, and XOR Cipher.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/encryption-decryption-tool.git
   cd encryption-decryption-tool
