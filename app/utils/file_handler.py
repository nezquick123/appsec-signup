import os
import uuid
from PIL import Image
from werkzeug.utils import secure_filename
from flask import current_app
import logging

# Set up logger
logger = logging.getLogger(__name__)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def save_picture(form_picture):
    """
    Validates and saves an uploaded picture.
    """
    # 1. Check extension
    if not allowed_file(form_picture.filename):
        raise ValueError("File extension not allowed.")

    # 2. Secure filename
    secure_name = secure_filename(form_picture.filename)
    random_hex = uuid.uuid4().hex
    _, f_ext = os.path.splitext(secure_name)
    picture_fn = random_hex + f_ext
    
    # Check if config is loaded
    if 'UPLOAD_FOLDER' not in current_app.config:
        logger.error("UPLOAD_FOLDER not set in config.py")
        raise ValueError("Server configuration error: UPLOAD_FOLDER missing.")

    picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], picture_fn)

    try:
        # 3. Verify it's an image
        img = Image.open(form_picture)
        img.verify()  # Check for file corruption
        
        # Reset file pointer
        form_picture.seek(0)
        img = Image.open(form_picture)
        
        # 4. Save
        # Ensure directory exists
        os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Saving the image creates a new file, naturally stripping most injected metadata/exif
        # This is safer and supports all image modes (Transparency, etc.)
        img.save(picture_path)
        
        return picture_fn
        
    except Exception as e:
        # Log the specific error to the terminal/docker logs
        logger.error(f"Image upload failed: {str(e)}")
        raise ValueError("Invalid image file detected.")