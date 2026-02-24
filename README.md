🔐 SecureVault – PKI-Based Secure File Sharing System

📌 Overview
SecureVault is an open-source cryptographic tool developed for the Practical Cryptography (ST6051CEM) module.
The system leverages Public Key Infrastructure (PKI) to provide:
Authentication
Data confidentiality
Data integrity
Secure key management
Hybrid encryption for secure file sharing
The application implements industry-standard cryptographic primitives including RSA-2048, AES, and RSA-OAEP.

🛡 Cryptographic Architecture
SecureVault follows a hybrid encryption model:

🔑 Key Management
RSA 2048-bit key pair generated per user
Public key stored in repository (database)
Private key encrypted using password-derived key
RSA public exponent: 65537
Padding: OAEP with SHA-256

🔐 Encryption Model
Files encrypted using AES (Fernet)
AES session key encrypted using recipient’s RSA public key
AES key decrypted using RSA private key
Only intended recipient can decrypt shared file

✍ Digital Signatures
RSA-based signing
Signature verification using sender’s public key
Ensures integrity and authenticity

🚫 Attack Mitigation
RSA-OAEP prevents chosen ciphertext attacks
SHA-256 prevents collision vulnerabilities
Login attempt rate limiting prevents brute-force attacks
Encrypted private key storage prevents key theft

🏗 System Features

User Registration & Authentication
RSA Key Pair Generation
Secure File Encryption & Sharing
Digital Signature Verification
Password-Protected Private Keys
Login Lockout Mechanism
SQLite PKI Repository
Multi-user Simulation

⚙ Installation (Local Setup)
1️⃣ Clone Repository
git clone https://github.com/yourusername/securevault.git
cd securevault

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run Application
python main.py

🐳 Docker Setup
Build Docker Image
docker build -t securevault .

Run Container
docker run -p 3000:3000 securevault

☸ Kubernetes Deployment (Minikube)
1️⃣ Start Minikube
minikube start

2️⃣ Use Minikube Docker Environment
eval $(minikube docker-env)
docker build -t securevault .

3️⃣ Deploy Application
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

4️⃣ Verify Pods
kubectl get pods

5️⃣ Access Application
minikube service securevault-service

🌍 Public Testing via ngrok
For demonstration purposes:
ngrok http 3000
Or if using NodePort:
ngrok http <node-port>
This generates a temporary HTTPS URL for external testing.

🔐 Security Notice
All sensitive data remains protected using:
RSA-2048 asymmetric encryption
AES symmetric encryption
RSA-OAEP padding with SHA-256
Password-encrypted private key storage
Exposing the service via ngrok is strictly for controlled demonstration and testing. Production deployments should use HTTPS with proper TLS certificates.

🗄 Database Structure
users
public_keys
shared_files
active_sessions
failed_login_attempts
The database acts as a lightweight PKI repository.

🧪 Testing & Validation
Multi-user file sharing simulation
Unauthorized decryption attempts fail
Signature verification tests
Account lockout testing
Hybrid encryption validation

🎥 Demonstration

YouTube Video Demonstration:
https://youtu.be/4yW3URe964o?si=VKudwdmAu8g7sWun

📂 GitHub Repository

Source Code:
https://github.com/snehadharel/SecureVault-Secure-File-Sharing-

📜 License
This project is open-source and available for academic use under the MIT License.

👩‍💻 Project Developer

Sneha Dharel
Student ID: 230231
Softwarica College of IT & E-Commerce
In collaboration with Coventry University

Module: Practical Cryptography (ST6051CEM)
Assignment: Open-Source Cryptographic Tool Development

🚀 Future Improvements
Implement PBKDF2 or scrypt for stronger password-based key derivation
Add Certificate Authority (CA) simulation
Implement forward secrecy using ephemeral Diffie-Hellman
Replace SQLite with secure enterprise PKI backend
Add TLS certificate-based authentication