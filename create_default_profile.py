from PIL import Image, ImageDraw
import os

def create_default_profile():
    # Create a 200x200 image with a light gray background
    img = Image.new('RGB', (200, 200), color='#f0f0f0')
    draw = ImageDraw.Draw(img)
    
    # Draw a circle
    draw.ellipse((20, 20, 180, 180), fill='#cccccc')
    
    # Draw a person silhouette
    draw.ellipse((70, 50, 130, 110), fill='#666666')  # Head
    draw.rectangle((85, 110, 115, 160), fill='#666666')  # Body
    
    # Save the image
    os.makedirs('static/profile_pictures', exist_ok=True)
    img.save('static/profile_pictures/default_profile.png')
    print("Default profile picture created successfully!")

if __name__ == '__main__':
    create_default_profile() 