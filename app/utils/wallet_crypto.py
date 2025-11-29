"""
Wallet Cryptographic Utilities

Handles P-256 key pair generation, HPKE decryption, and payload signing
for Zynk Labs wallet creation flow.
"""

import base64
import json
import logging
import hashlib
from typing import Tuple, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.backends import default_backend
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
import base58

logger = logging.getLogger(__name__)

# P-256 curve order for canonical signature normalization
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def generate_keypair() -> Tuple[str, str]:
    """Generate P-256 key pair. Returns: (private_hex_64, public_hex_130_uncompressed)"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_hex = format(private_key.private_numbers().private_value, '064x')
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_hex, public_bytes.hex()


# HPKE Decryption Functions
def bytes_from_hex(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()

def is_hex_string(s: str) -> bool:
    """Check if a string is valid hexadecimal."""
    try:
        if len(s) % 2 != 0:
            return False
        int(s, 16)
        return True
    except ValueError:
        return False

def decode_bundle(bundle_str: str) -> bytes:
    """Decode a credential bundle from either hex or bs58check format."""
    if is_hex_string(bundle_str):
        return bytes.fromhex(bundle_str)
    return base58.b58decode_check(bundle_str)

def compress_public_key(uncompressed_key: bytes) -> bytes:
    """Compress an uncompressed P-256 public key."""
    if len(uncompressed_key) != 65 or uncompressed_key[0] != 0x04:
        raise ValueError("Invalid uncompressed public key format")
    x = uncompressed_key[1:33]
    y = uncompressed_key[33:65]
    prefix = 0x02 if y[-1] % 2 == 0 else 0x03
    return bytes([prefix]) + x

def uncompress_public_key(compressed_key: bytes) -> bytes:
    """Uncompress a compressed P-256 public key."""
    if len(compressed_key) != 33:
        raise ValueError(f"Invalid compressed public key length: {len(compressed_key)}")
    if compressed_key[0] not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed public key prefix: {hex(compressed_key[0])}")

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        compressed_key
    )
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return uncompressed

def derive_public_key_from_private(private_key_hex: str) -> Tuple[bytes, bytes]:
    """Derive public key from private key."""
    private_key_bytes = bytes_from_hex(private_key_hex)
    private_value = int.from_bytes(private_key_bytes, byteorder='big')
    private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

    public_key = private_key.public_key()
    compressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return compressed, uncompressed

def decrypt_credential_bundle(bundle_str: str, ephemeral_private_key: str) -> Dict[str, str]:
    """Decrypt a credential bundle using HPKE."""
    bundle_bytes = decode_bundle(bundle_str)
    first_byte = bundle_bytes[0]

    if first_byte == 0x04:
        if len(bundle_bytes) < 65:
            raise ValueError(f"Bundle too small for uncompressed key: {len(bundle_bytes)} bytes")
        enc = bundle_bytes[:65]
        ciphertext = bundle_bytes[65:]
    elif first_byte in (0x02, 0x03):
        if len(bundle_bytes) < 33:
            raise ValueError(f"Bundle too small for compressed key: {len(bundle_bytes)} bytes")
        compressed_encapped_key = bundle_bytes[:33]
        ciphertext = bundle_bytes[33:]
        enc = uncompress_public_key(compressed_encapped_key)
    else:
        raise ValueError(f"Invalid encapped key prefix: {hex(first_byte)}")

    if len(ciphertext) < 16:
        raise ValueError(f"Ciphertext too small: {len(ciphertext)} bytes")

    suite = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM
    )

    _, receiver_public_key = derive_public_key_from_private(ephemeral_private_key)

    private_key_bytes = bytes_from_hex(ephemeral_private_key)
    private_value = int.from_bytes(private_key_bytes, byteorder='big')
    pyca_private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

    recipient_key = KEMKey.from_pyca_cryptography_key(pyca_private_key)

    aad = enc + receiver_public_key
    info = b"turnkey_hpke"

    recipient_ctx = suite.create_recipient_context(
        enc=enc,
        skr=recipient_key,
        info=info
    )

    plaintext = recipient_ctx.open(ciphertext, aad)
    private_key_hex = bytes_to_hex(plaintext)

    temp_compressed, _ = derive_public_key_from_private(private_key_hex)
    temp_public_key = bytes_to_hex(temp_compressed)
    temp_private_key = private_key_hex

    return {
        'tempPublicKey': temp_public_key,
        'tempPrivateKey': temp_private_key
    }


# Payload Signing Functions
def sha256_hex(input_str: str) -> str:
    """SHA-256 hash of UTF-8 string, returns hex."""
    return hashlib.sha256(input_str.encode('utf-8')).hexdigest()

def to_base64url(s: str) -> str:
    """Base64URL encode a string."""
    b64 = base64.b64encode(s.encode('utf-8')).decode('ascii')
    return b64.replace('+', '-').replace('/', '_').rstrip('=')

def make_canonical_signature(r: int, s: int) -> tuple:
    """Ensure signature is in canonical (low-S) form."""
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r, s

def get_compressed_public_key(private_key_hex: str) -> str:
    """Derive compressed public key from private key."""
    private_value = int(private_key_hex, 16)
    private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    return public_key_bytes.hex()

def sign_payload_with_api_key(payload: str, api_private_key: str, api_public_key: str = None) -> str:
    """Sign payload using API key pair."""
    if api_public_key is None:
        api_public_key = get_compressed_public_key(api_private_key)

    if len(api_public_key) != 66:
        raise ValueError(f"Public key must be 66 hex chars (compressed), got {len(api_public_key)}")

    if api_public_key[:2] not in ('02', '03'):
        raise ValueError(f"Public key must start with 02 or 03 (compressed), got {api_public_key[:2]}")

    hash_hex = sha256_hex(payload)
    hash_bytes = bytes.fromhex(hash_hex)

    private_value = int(api_private_key, 16)
    private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())

    signature_der = private_key.sign(
        hash_bytes,
        ECDSA(hashes.SHA256())
    )

    r, s = decode_dss_signature(signature_der)
    r, s = make_canonical_signature(r, s)
    canonical_der = encode_dss_signature(r, s)

    der_hex = canonical_der.hex()

    stamp_obj = {
        'publicKey': api_public_key,
        'scheme': 'SIGNATURE_SCHEME_TK_API_P256',
        'signature': der_hex,
    }

    stamp_json = json.dumps(stamp_obj, separators=(',', ':'))
    stamp_b64url = to_base64url(stamp_json)

    return stamp_b64url



