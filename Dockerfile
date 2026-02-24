# Use official Python slim image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Upgrade pip to latest version
RUN pip install --upgrade pip

# Copy requirements file
COPY requirements.txt .

# Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project files
COPY . .

# Expose the port your Flask app will run on
EXPOSE 5000

# Set environment variable to avoid buffering issues
ENV PYTHONUNBUFFERED=1

# Run your main Python file
CMD ["python", "main.py"]
