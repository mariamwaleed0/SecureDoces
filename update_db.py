from app import create_app
from models import db

app = create_app()

with app.app_context():
    # Add profile_picture column
    db.engine.execute('ALTER TABLE user ADD COLUMN profile_picture VARCHAR(255) DEFAULT "default_profile.png"')
    print("Database updated successfully!") 