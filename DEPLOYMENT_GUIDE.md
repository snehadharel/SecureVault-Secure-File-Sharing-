SecureVault Deployment Guide
This document explains how SecureVault was deployed locally using Minikube (Kubernetes) and exposed publicly using ngrok for demonstration purposes.

🧩 1. Starting Minikube
Minikube is used to run a local Kubernetes cluster.
▶ Start Minikube
  minikube start
Verify Minikube status:
  minikube status

📦 2. Deploying the Application
Apply the Kubernetes configuration files:
  kubectl apply -f deployment.yaml
  kubectl apply -f service.yaml

🔍 3. Verify Deployment
Check running pods:
  kubectl get pods
Check services:
  kubectl get svc
The frontend service is exposed using NodePort on port 30080.

🌐 4. Accessing the Application Locally
Get Minikube IP:
  minikube ip
Open in browser:
  http://<minikube-ip>:30080
Example:
  http://192.168.49.2:30080

⚠ Note: localhost:30080 will not work because Minikube runs inside a virtualized environment.

🔓 5. Exposing Application Publicly Using ngrok
Since Minikube runs locally, ngrok is used to create a secure public tunnel.
Run:
  ngrok http <minikube-ip>:30080
ngrok will generate a public HTTPS link like:
  https://xxxxx.ngrok-free.app
This link can be shared for external demonstration.

🛡 6. Important Notes
Minikube is used for local Kubernetes deployment.
ngrok provides temporary public access.
This setup is intended for testing and academic demonstration.
For production deployment, a cloud-based Kubernetes service should be used.
