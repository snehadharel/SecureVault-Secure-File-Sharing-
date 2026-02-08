SecureVault – Secure File Sharing System using Hybrid Cryptography

SecureVault is an open-source secure file sharing system designed to ensure confidentiality, integrity, and authentication of digital files using modern cryptographic techniques. The system leverages hybrid cryptography, combining symmetric encryption (AES), asymmetric encryption (RSA), and cryptographic hashing (SHA-256) to provide secure and efficient file sharing between authenticated users.

This project was developed as part of the **Practical Cryptography (ST6051CEM)** coursework at **Softwarica College of IT & E-Commerce**, in collaboration with Coventry University.

---

🔐 Key Features

- Hybrid encryption using **AES-256** and **RSA-2048**
- Secure file upload, sharing, and download
- Public Key Infrastructure (PKI)-based authentication
- Digital signatures for integrity verification
- Secure private key storage
- Role-based access control (Admin/User)
- Metadata extraction from common file formats
- Protection against common attacks (MITM, replay, brute force)
- Dockerized deployment support
- Open-source and extensible architecture

---

🧠 Cryptographic Techniques Used

| Technique | Algorithm | Purpose |
|---------|----------|---------|
| Symmetric Encryption | AES-256 | Fast encryption of file contents |
| Asymmetric Encryption | RSA-2048 | Secure key exchange and authentication |
| Hashing | SHA-256 | Integrity verification and password hashing |
| Digital Signatures | RSA + SHA-256 | Data integrity and non-repudiation |

---

🏗️ System Architecture (Overview)

SecureVault follows a layered architecture:

- **User Interface Layer** – Handles user interaction (Tkinter GUI)
- **Application Logic Layer** – Manages authentication, authorization, and workflows
- **Cryptographic Engine** – Performs encryption, decryption, and hashing
- **Data Storage Layer** – Stores encrypted files, keys, and user data (SQLite + JSON)

---
🧪 Testing

The system has been tested using:

Manual unit testing of cryptographic operations

Multi-user file sharing simulations

Unauthorized access and attack simulations

Performance testing for different file sizes

Testing ensures that:

Only authorized users can decrypt files

Incorrect keys cannot decrypt content

Session and access controls function correctly
---
📄 Documentation

Detailed documentation explaining:

Cryptographic design decisions

Security features

System architecture

Real-world use cases

is provided in the coursework report.
---

👩‍💻 Developer

Name: Sneha Dharel

Student ID: 230231

Module: Practical Cryptography (ST6051CEM)
---

🚀 Installation & Setup

🔹 Prerequisites
- Python 3.8 or higher
- Git
- Docker (optional)

🔹 Clone Repository
```bash
git clone https://github.com/your-username/SecureVault.git
cd SecureVault
