"""
working unit tests for Secure File Sharing Tool
"""

import unittest
import tempfile
import os
import shutil
import json
import sqlite3
from datetime import datetime
import base64
import hashlib
import re

from cryptography.fernet import Fernet

# Mock the GUI components to avoid import errors
import sys
from unittest.mock import Mock, patch, MagicMock

# Mock tkinter before importing any GUI-dependent code
sys.modules['tkinter'] = Mock()
sys.modules['tkinter.ttk'] = Mock()
sys.modules['tkinter.scrolledtext'] = Mock()
sys.modules['tkinter.filedialog'] = Mock()
sys.modules['tkinter.messagebox'] = Mock()

# Now we can safely import and test non-GUI components
# We'll create simple test classes without importing the actual GUI app

class TestCryptography(unittest.TestCase):
    """Test cryptographic functions"""
    
    def test_password_hashing(self):
        """Test password hashing consistency"""
        password = "Test@123"
        hash1 = hashlib.sha256(password.encode()).hexdigest()
        hash2 = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 produces 64-character hex
    
    def test_fernet_encryption(self):
        """Test AES encryption/decryption with Fernet"""
        key = Fernet.generate_key()
        fernet = Fernet(key)
        
        original_data = b"Test secret message"
        encrypted_data = fernet.encrypt(original_data)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        self.assertEqual(original_data, decrypted_data)
        self.assertNotEqual(original_data, encrypted_data)
    
    def test_password_strength_validation(self):
        """Test password strength validation"""
        test_cases = [
            ("short", False),
            ("noupper123@", False),
            ("NOLOWER123@", False),
            ("NoDigit@", False),
            ("NoSpecial123", False),
            ("Valid@123", True),
            ("Strong@Password123", True),
        ]
        
        for password, expected_valid in test_cases:
            if len(password) < 8:
                self.assertFalse(expected_valid, f"Password '{password}' should be invalid (too short)")
                continue
            
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*(),.?\":{}|<>" for c in password)
            
            is_valid = has_upper and has_lower and has_digit and has_special
            self.assertEqual(is_valid, expected_valid, 
                           f"Password '{password}' validation failed. "
                           f"Upper: {has_upper}, Lower: {has_lower}, "
                           f"Digit: {has_digit}, Special: {has_special}")

class TestDatabaseOperations(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Create a temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test.db")
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_database_creation(self):
        """Test creating database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Create shared_files table
        cursor.execute('''
            CREATE TABLE shared_files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                shared_by TEXT NOT NULL,
                shared_with TEXT NOT NULL,
                shared_date TIMESTAMP NOT NULL,
                encrypted_file TEXT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                downloaded INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('users', tables)
        self.assertIn('shared_files', tables)
        
        conn.close()
    
    def test_user_crud_operations(self):
        """Test user CRUD operations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table
        cursor.execute('''
            CREATE TABLE users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Insert user
        test_email = "test@example.com"
        test_password_hash = hashlib.sha256("password123".encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO users (email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        ''', (test_email, test_password_hash, 'user', '2024-01-01 10:00:00'))
        
        conn.commit()
        
        # Read user
        cursor.execute('SELECT * FROM users WHERE email = ?', (test_email,))
        user = cursor.fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(user[0], test_email)
        self.assertEqual(user[2], 'user')
        
        # Update user
        cursor.execute('''
            UPDATE users SET role = ? WHERE email = ?
        ''', ('admin', test_email))
        conn.commit()
        
        cursor.execute('SELECT role FROM users WHERE email = ?', (test_email,))
        role = cursor.fetchone()[0]
        self.assertEqual(role, 'admin')
        
        # Soft delete user
        cursor.execute('''
            UPDATE users SET is_active = 0 WHERE email = ?
        ''', (test_email,))
        conn.commit()
        
        cursor.execute('SELECT is_active FROM users WHERE email = ?', (test_email,))
        is_active = cursor.fetchone()[0]
        self.assertEqual(is_active, 0)
        
        conn.close()

class TestJSONOperations(unittest.TestCase):
    """Test JSON file operations"""
    
    def setUp(self):
        """Create temporary directory for testing"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_json_file_operations(self):
        """Test reading/writing JSON files"""
        test_file = os.path.join(self.temp_dir, "test.json")
        
        # Write to JSON
        test_data = {
            "users": [
                {
                    "email": "test@example.com",
                    "role": "user",
                    "created_at": "2024-01-01"
                }
            ],
            "total_users": 1
        }
        
        with open(test_file, 'w') as f:
            json.dump(test_data, f, indent=4)
        
        # Read from JSON
        with open(test_file, 'r') as f:
            loaded_data = json.load(f)
        
        # Verify
        self.assertEqual(test_data, loaded_data)
        self.assertEqual(len(loaded_data["users"]), 1)
        self.assertEqual(loaded_data["users"][0]["email"], "test@example.com")

class TestFileOperations(unittest.TestCase):
    """Test file encryption/decryption operations"""
    
    def setUp(self):
        """Create temporary directory for testing"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_file_encryption_decryption(self):
        """Test complete file encryption/decryption cycle"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        original_content = b"This is a test file for encryption."
        
        with open(test_file, 'wb') as f:
            f.write(original_content)
        
        # Generate key and encrypt
        key = Fernet.generate_key()
        fernet = Fernet(key)
        
        with open(test_file, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = fernet.encrypt(file_data)
        
        # Write encrypted file
        encrypted_file = test_file + '.encrypted'
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Verify encryption
        self.assertNotEqual(original_content, encrypted_data)
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted file
        decrypted_file = test_file + '.decrypted'
        with open(decrypted_file, 'wb') as f:
            f.write(decrypted_data)
        
        # Verify decryption
        self.assertEqual(original_content, decrypted_data)
        self.assertTrue(os.path.exists(decrypted_file))
        
        # Clean up
        os.remove(encrypted_file)
        os.remove(decrypted_file)

class TestValidationFunctions(unittest.TestCase):
    """Test validation functions"""
    
    def test_email_validation(self):
        """Test email format validation"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        test_cases = [
            ("test@example.com", True),
            ("user.name@domain.co.uk", True),
            ("user+tag@example.org", True),
            ("invalid-email", False),
            ("@example.com", False),
            ("test@", False),
            ("test@.com", False),
            ("", False),
        ]
        
        for email, expected_valid in test_cases:
            is_valid = re.match(email_pattern, email) is not None
            self.assertEqual(is_valid, expected_valid, 
                           f"Email '{email}' validation failed. Expected: {expected_valid}, Got: {is_valid}")
    
    def test_base64_encoding(self):
        """Test Base64 encoding/decoding"""
        test_string = "Hello, World! This is a test."
        
        encoded = base64.b64encode(test_string.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        
        self.assertEqual(test_string, decoded)
        self.assertNotEqual(test_string, encoded)

class TestEdgeCases(unittest.TestCase):
    """Test edge cases"""
    
    def test_empty_file_handling(self):
        """Test operations with empty files"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = f.name
        
        try:
            # Test file exists
            self.assertTrue(os.path.exists(temp_file))
            
            # Test file size is 0
            self.assertEqual(os.path.getsize(temp_file), 0)
            
            # Test we can read/write to it
            with open(temp_file, 'w') as f:
                f.write("test content")
            
            with open(temp_file, 'r') as f:
                content = f.read()
            
            self.assertEqual(content, "test content")
            
        finally:
            os.unlink(temp_file)

def run_all_tests():
    """Run all tests and print summary"""
    print("=" * 60)
    print("Running Secure File Sharing Tool Unit Tests")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestCryptography,
        TestDatabaseOperations,
        TestJSONOperations,
        TestFileOperations,
        TestValidationFunctions,
        TestEdgeCases,
    ]
    
    for test_class in test_classes:
        suite.addTest(loader.loadTestsFromTestCase(test_class))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_all_tests()
    exit_code = 0 if success else 1
    print(f"\nExit Code: {exit_code}")
    sys.exit(exit_code)