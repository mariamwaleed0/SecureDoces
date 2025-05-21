from app import app
from models import db, User
from werkzeug.security import generate_password_hash

def update_password_hashes():
    with app.app_context():
        users = User.query.all()
        for user in users:
            if user.password_hash.startswith('scrypt:'):
                # Generate a temporary password
                temp_password = 'Temp123!@#'
                # Update the hash with the new method
                user.password_hash = generate_password_hash(temp_password, method='pbkdf2:sha256')
                print(f"Updated password hash for user: {user.email}")
        
        db.session.commit()
        print("All password hashes have been updated successfully!")

if __name__ == '__main__':
    update_password_hashes() 