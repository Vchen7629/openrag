import io
from pypdf import PdfWriter

cases = [
    ('test_RC4-40.pdf', 'RC4-40', 'password', None),
    ('test_RC4-128.pdf', 'RC4-128', 'password', None),
    ('test_AES-128.pdf', 'AES-128', 'password', None),
    ('test_AES-256.pdf', 'AES-256', 'password', None),
    ('test_owner_only.pdf', 'AES-256', '', 'ownerpass'),
]

for filename, alg, user_pwd, owner_pwd in cases:
    w = PdfWriter()
    w.add_blank_page(100, 100)
    w.encrypt(user_pwd, owner_password=owner_pwd, algorithm=alg)
    buf = io.BytesIO()
    w.write(buf)
    with open(filename, 'wb') as f:
        f.write(buf.getvalue())
    print(f'Created {filename}')