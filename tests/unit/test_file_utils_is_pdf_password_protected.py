import io

import pytest
from pypdf import PdfWriter

from utils.file_utils import (
    is_pdf_password_protected_bytes,
    is_pdf_password_protected_pypdf,
)


def _make_encrypted_pdf(algorithm: str) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.encrypt("userpass", algorithm=algorithm)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _make_plain_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _make_owner_only_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.encrypt("", owner_password="ownerpass", algorithm="AES-256")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.mark.parametrize(
    argnames="content, expected", 
    argvalues=[
        (b"%PDF-1.7\ntrailer<</Encrypt 1 0 R>>", True),
        (b"%PDF-1.7\ntrailer<<>>", False),
        (b"not a pdf", False),
        (b"", False),
        (b"%PDF-", False),
    ],    
)
def test_bytes_synthetic(content: bytes, expected: bool) -> None:
    assert is_pdf_password_protected_bytes(content) == expected


@pytest.mark.parametrize("algorithm", ["RC4-40", "RC4-128", "AES-128", "AES-256"])
def test_bytes_detects_encrypted_pdf(algorithm: str) -> None:
    assert is_pdf_password_protected_bytes(_make_encrypted_pdf(algorithm)) is True


def test_bytes_plain_pdf_returns_false() -> None:
    assert is_pdf_password_protected_bytes(_make_plain_pdf()) is False


@pytest.mark.parametrize("algorithm", ["RC4-40", "RC4-128", "AES-128", "AES-256"])
def test_pypdf_detects_encrypted_pdf(algorithm: str) -> None:
    assert is_pdf_password_protected_pypdf(_make_encrypted_pdf(algorithm)) is True


def test_pypdf_plain_pdf_returns_false() -> None:
    assert is_pdf_password_protected_pypdf(_make_plain_pdf()) is False


def test_pypdf_owner_only_pdf_returns_false() -> None:
    assert is_pdf_password_protected_pypdf(_make_owner_only_pdf()) is False


@pytest.mark.parametrize(
    "content",
    [b"not a pdf", b"", b"%PDF-1.7\ngarbage"],
)
def test_pypdf_invalid_content_returns_false(content: bytes) -> None:
    assert is_pdf_password_protected_pypdf(content) is False