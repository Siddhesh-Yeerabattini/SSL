from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.x509 import load_pem_x509_certificate
from pathlib import Path

# Specify the path to the .pfx file
pfx_file = r"C:\Users\siddh\OneDrive\Desktop\New folder\test.pfx"  # Replace with your .pfx file path
password = b"hafeez"  # Replace with your .pfx password

# Output paths for the .pem components
private_key_pem_path = "private_key.pem"
certificate_pem_path = "certificate.pem"
combined_pem_path = "combined.pem"

try:
    # Read the .pfx file
    with open(pfx_file, "rb") as file:
        pfx_data = file.read()

    # Load the private key, certificate, and any additional certificates
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(pfx_data, password)

    # Save the private key to a .pem file
    if private_key:
        with open(private_key_pem_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            ))
        print(f"Private key saved to {private_key_pem_path}")

    # Save the certificate to a .pem file
    if certificate:
        with open(certificate_pem_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(Encoding.PEM))
        print(f"Certificate saved to {certificate_pem_path}")

    # Combine the private key and certificate into a single .pem file
    with open(combined_pem_path, "wb") as combined_file:
        if private_key:
            combined_file.write(private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            ))
        if certificate:
            combined_file.write(certificate.public_bytes(Encoding.PEM))
        print(f"Combined PEM saved to {combined_pem_path}")

except Exception as e:
    print(f"An error occurred: {e}")
