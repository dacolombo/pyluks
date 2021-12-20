# Import dependencies
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime

def generate_private_key(key_size, key_file):
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    with open(key_file, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    return key


def generate_self_signed_cert(CN='localhost', cert_file='/etc/luks/gunicorn-cert.pem', expiration_days=3650, key_size=4096, key_file='/etc/luks/gunicorn-key.pem'):

    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, CN)])

    key = generate_private_key(key_size=key_size, key_file=key_file)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
    # The certificate will be valid for 3650 days
        datetime.datetime.utcnow() + datetime.timedelta(days=expiration_days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(CN)]), critical=False,
    # Sign the certificate with private key
    ).sign(key, hashes.SHA256())

    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
