"""User file uploads: validated storage plus public serving."""
from __future__ import annotations

import os
import re
import secrets

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import AsyncSessionLocal, get_db
from ..deps import csrf_protect, log_audit, require_user
from ..models import StoredFile, User
from ..render import Redirect, T
from ..security import RateLimiter, get_client_ip

router = APIRouter(dependencies=[Depends(csrf_protect)])
upload_limiter = RateLimiter()

MAX_UPLOAD_SIZE = 10 * 1024 * 1024

# extension -> (mime type, magic bytes). SVG is deliberately excluded (XSS).
ALLOWED_UPLOADS: dict[str, tuple[str, bytes | None]] = {
    "png": ("image/png", b"\x89PNG"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    "gif": ("image/gif", b"GIF8"),
    "webp": ("image/webp", None),
    "ico": ("image/x-icon", b"\x00\x00\x01\x00"),
    "pdf": ("application/pdf", b"%PDF"),
}

_STORED_NAME_RE = re.compile(r"^[a-f0-9]{32}\.[a-z0-9]+$")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class UploadError(Exception):
    pass


def _check_magic(ext: str, data: bytes) -> bool:
    if ext == "webp":
        return data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    magic = ALLOWED_UPLOADS[ext][1]
    return data[: len(magic)] == magic


async def store_upload(upload: UploadFile, user_id: int, db: AsyncSession) -> StoredFile:
    """Validate and persist an uploaded file. Raises UploadError on rejection."""
    data = await upload.read()
    if not data:
        raise UploadError("Empty file.")
    if len(data) > MAX_UPLOAD_SIZE:
        raise UploadError("File is too large (max 10 MB).")
    original = (upload.filename or "").strip()
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_UPLOADS:
        raise UploadError(
            "File type not allowed. Allowed: png, jpg, gif, webp, ico, pdf."
        )
    if not _check_magic(ext, data):
        raise UploadError("File contents do not match its extension.")
    stored_name = secrets.token_hex(16) + "." + ext
    upload_dir = os.path.join(settings.DATA_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    with open(os.path.join(upload_dir, stored_name), "wb") as f:
        f.write(data)
    row = StoredFile(
        user_id=user_id,
        stored_name=stored_name,
        original_name=original[:255],
        mime=ALLOWED_UPLOADS[ext][0],
        size=len(data),
    )
    db.add(row)
    await db.flush()
    return row


def delete_stored_file(row: StoredFile) -> None:
    """Remove the file from disk. Never raises."""
    try:
        path = os.path.join(settings.DATA_DIR, "uploads", row.stored_name)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


@router.get("/files")
async def files_list(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    rows = (
        await db.execute(
            select(StoredFile)
            .where(StoredFile.user_id == user.id)
            .order_by(StoredFile.created_at.desc())
        )
    ).scalars().all()
    return await T(request, "files/list.html", user=user, files=rows)


@router.post("/files/upload")
@router.post("/files")
async def file_upload(
    request: Request,
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not upload_limiter.allowed(f"upload:{user.id}", 60, 3600):
        return Redirect("/files", "Upload rate limit reached.", toast_type="error")
    try:
        await store_upload(file, user.id, db)
    except UploadError as e:
        return Redirect("/files", str(e), toast_type="error")
    await log_audit(db, "file_upload", detail=f"name={file.filename}",
                    actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/files", "File uploaded.")


@router.post("/files/{file_id}/delete")
async def file_delete(file_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    row = await db.get(StoredFile, file_id)
    if row is None or (row.user_id != user.id and user.role != "admin"):
        return Redirect("/files", "File not found.", toast_type="error")
    delete_stored_file(row)
    await db.delete(row)
    await log_audit(db, "file_delete", detail=f"name={row.stored_name}",
                    actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/files", "File deleted.")


@router.get("/uploads/{stored_name}")
async def serve_upload(stored_name: str):
    """Serve a stored file publicly with safe content headers."""
    if not _STORED_NAME_RE.fullmatch(stored_name):
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse("Not found", status_code=404)
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(StoredFile).where(StoredFile.stored_name == stored_name)
            )
        ).scalar_one_or_none()
    if row is None:
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse("Not found", status_code=404)
    path = os.path.join(settings.DATA_DIR, "uploads", stored_name)
    if not os.path.isfile(path):
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse("Not found", status_code=404)
    safe_name = _SAFE_FILENAME_RE.sub("_", row.original_name or stored_name)
    return FileResponse(
        path,
        media_type=row.mime,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "public, max-age=86400",
            "Content-Disposition": f'inline; filename="{safe_name}"',
        },
    )
