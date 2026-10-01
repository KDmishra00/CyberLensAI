"""Upload module - handles file upload, validation, and storage (FR-1 to FR-4)"""
import os
import tempfile
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'log'}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB (FR-3)


def allowed_file(filename):
    """Check if file extension is in the supported set."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file(filepath):
    """Validate uploaded file: check size, extension, and readability (FR-3)."""
    if not os.path.exists(filepath):
        return {'valid': False, 'error': 'File not found'}

    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        return {
            'valid': False,
            'error': f'File size ({file_size / (1024*1024):.1f} MB) exceeds the {MAX_FILE_SIZE // (1024*1024)} MB limit'
        }

    filename = os.path.basename(filepath)
    if not allowed_file(filename):
        return {'valid': False, 'error': 'Invalid file type. Allowed: .csv, .xlsx, .log'}

    # Readability check — make sure the file is not corrupted
    try:
        ext = filename.rsplit('.', 1)[1].lower()
        if ext == 'csv':
            import pandas as pd
            pd.read_csv(filepath, nrows=1)
        elif ext == 'xlsx':
            import pandas as pd
            pd.read_excel(filepath, nrows=1)
        elif ext == 'log':
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                f.readline()
    except Exception as e:
        return {'valid': False, 'error': f'File appears corrupted or unreadable: {str(e)}'}

    info = {
        'filename': filename,
        'size': file_size,
        'size_display': _format_size(file_size),
        'extension': ext,
    }

    return {'valid': True, 'info': info, 'error': None}


def save_uploaded_file(file):
    """Save uploaded file to temporary storage (NFR-5.2c).
    Returns the path of the saved temporary file.
    """
    filename = secure_filename(file.filename)
    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, f"cyberlens_{os.urandom(8).hex()}_{filename}")
    file.save(filepath)
    return filepath


def cleanup_file(filepath):
    """Remove temporary file after analysis is complete (NFR-5.2c)."""
    try:
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
    except Exception:
        pass


def _format_size(size_bytes):
    """Format bytes into a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
