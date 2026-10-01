"""Upload validation and safe storage.

Files are treated strictly as data: we look at bytes, never run anything.
The original filename is only ever used for display and for the extension
check; on disk everything gets a random name inside tmp/<analysis_id>/.
"""
import os
import re
import secrets
import zipfile

from config import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    MAX_XLSX_DECOMPRESSED,
    TMP_DIR,
)


class UploadError(ValueError):
    """Raised when a file must be rejected. The message goes straight to the UI."""


_NON_PRINTABLE_RATIO_LIMIT = 0.10  # more than this and we call it binary


def _friendly_type(filename: str) -> str:
    name = filename.strip()
    if name.startswith("."):
        return "a dotfile"
    ext = os.path.splitext(name)[1].lower()
    return f"a {ext} file" if ext else "a file without an extension"


def validate_extension(filename: str) -> str:
    """Return the lowercase extension, or raise with a specific message."""
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise UploadError(
            f"That file is {_friendly_type(filename)}. "
            "CyberLens accepts .csv, .xlsx and .log files."
        )
    return ext


def _looks_binary(head: bytes) -> bool:
    if b"\x00" in head:
        return True
    if not head:
        return False
    # Count bytes outside printable ASCII / common whitespace. Text files,
    # including latin-1 logs, stay well under this ratio.
    printable = sum(1 for b in head if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(head)) < (1 - _NON_PRINTABLE_RATIO_LIMIT)


def _validate_xlsx(path: str) -> None:
    """XLSX must be a plain zip with the expected parts and no macros."""
    if not zipfile.is_zipfile(path):
        raise UploadError(
            "This .xlsx file is not a valid Excel workbook (it is not a zip archive)."
        )
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if not any(n == "[Content_Types].xml" for n in names):
                raise UploadError("This file is named .xlsx but has no Excel structure inside.")
            if any("vbaProject.bin" in n for n in names):
                raise UploadError(
                    "This workbook contains macros. CyberLens rejects macro-enabled files for safety."
                )
            total_uncompressed = sum(zi.file_size for zi in zf.infolist())
            if total_uncompressed > MAX_XLSX_DECOMPRESSED:
                raise UploadError(
                    "This workbook decompresses to more than 200 MB, which looks like a zip bomb. Rejected."
                )
    except zipfile.BadZipFile:
        raise UploadError("This .xlsx file is corrupt and could not be opened.")


def validate_content(path: str, ext: str) -> None:
    """Sanity-check file content before any parsing happens."""
    size = os.path.getsize(path)
    if size == 0:
        raise UploadError("The file is empty (0 bytes). Nothing to analyse.")
    with open(path, "rb") as fh:
        head = fh.read(8192)
    if ext == ".xlsx":
        _validate_xlsx(path)
        return
    if _looks_binary(head):
        raise UploadError(
            "This file does not look like text. CyberLens reads data files, not binaries."
        )
    # CSV and log files must decode as text; utf-8 first, latin-1 as fallback.
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=encoding, errors="strict") as fh:
                fh.read(65536)
            return
        except UnicodeDecodeError:
            continue
    raise UploadError("This file could not be decoded as text (tried UTF-8 and Latin-1).")


def save_upload(file_storage, analysis_id: str) -> tuple[str, str, int]:
    """Validate and store an uploaded file under tmp/<analysis_id>/.

    Returns (path, original_name, size). Raises UploadError with a message
    meant for the UI when anything is off.
    """
    original_name = os.path.basename(file_storage.filename or "")
    if not original_name:
        raise UploadError("No file was selected.")
    ext = validate_extension(original_name)

    os.makedirs(os.path.join(TMP_DIR, analysis_id), exist_ok=True)
    stored_name = f"upload{ext}"
    path = os.path.join(TMP_DIR, analysis_id, stored_name)
    file_storage.save(path)

    size = os.path.getsize(path)
    if size > MAX_UPLOAD_BYTES:
        os.remove(path)
        raise UploadError("This file is larger than the 20 MB limit.")
    try:
        validate_content(path, ext)
    except UploadError:
        os.remove(path)
        raise
    return path, original_name, size


def new_analysis_id() -> str:
    """A random id used as the folder name; also hard to guess in URLs."""
    return secrets.token_hex(16)


def analysis_dir(analysis_id: str) -> str:
    """Absolute path for this analysis, refusing anything that escapes tmp/."""
    safe = re.fullmatch(r"[0-9a-f]{32}", analysis_id or "")
    if not safe:
        raise UploadError("Unknown analysis id.")
    return os.path.join(TMP_DIR, analysis_id)
