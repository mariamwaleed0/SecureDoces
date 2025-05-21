import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash
import os
import secrets
import string

def generate_secure_password(length=16):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def init_database():
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=''
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database if not exists
            cursor.execute("CREATE DATABASE IF NOT EXISTS secure_docs_db")
            cursor.execute("USE secure_docs_db")
            
            # Read and execute schema.sql
            with open('schema.sql', 'r', encoding='utf-8') as file:
                schema = file.read()
                # Split the schema into individual statements
                statements = schema.split(';')
                for statement in statements:
                    if statement.strip():
                        cursor.execute(statement)
            
            # Create default admin user if not exists
            admin_email = 'admin@securedocs.com'
            cursor.execute("SELECT id FROM user WHERE email = %s", (admin_email,))
            if not cursor.fetchone():
                # Generate secure password
                admin_password = generate_secure_password()
                password_hash = generate_password_hash(admin_password)
                
                cursor.execute("""
                    INSERT INTO user (email, name, password_hash, role, is_active)
                    VALUES (%s, %s, %s, %s, %s)
                """, (admin_email, 'System Administrator', password_hash, 'admin', True))
                
                # Save admin credentials to a secure file
                with open('.admin_credentials', 'w') as f:
                    f.write(f"Email: {admin_email}\nPassword: {admin_password}")
                
                # Set secure file permissions
                os.chmod('.admin_credentials', 0o600)
            
            connection.commit()
            print("Database initialized successfully!")
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("Database connection closed.")

if __name__ == "__main__":
    init_database() 
