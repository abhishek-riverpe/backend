from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def generate_keypair() -> Tuple[str, str]:
    """Generate P-256 key pair. Returns: (private_hex_64, public_hex_130_uncompressed)"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_hex = format(private_key.private_numbers().private_value, '064x')
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_hex, public_bytes.hex()


if __name__ == "__main__":
    priv, pub = generate_keypair()
    
    with open('ephemeral_private.hex', 'w') as f:
        f.write(priv)
    with open('ephemeral_public.hex', 'w') as f:
        f.write(pub)
    
    print('Private key saved to: ephemeral_private.hex')
    print('Public key saved to: ephemeral_public.hex')
    print('')
    print('Private key length:', len(priv), 'hex chars')
    print('Public key length:', len(pub), 'hex chars')
    print('Public key prefix:', pub[:2])
    print('')
    print('Use this public key in start-session API:')
    print(pub)