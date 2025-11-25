"""
Wallet Cryptography Utilities

Handles P-256 key pair generation, credential bundle decryption, and payload signing
for Zynk Labs wallet creation flow.
"""

import json
import base64
import hashlib
import logging
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def generate_p256_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    Generate a P-256 (secp256r1) ephemeral key pair.
    
    Returns:
        Tuple of (private_key, uncompressed_public_key_bytes)
        Public key is in uncompressed format: 0x04 + 32 bytes X + 32 bytes Y (65 bytes total)
    """
    # Generate P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    # Get public key numbers
    public_numbers = public_key.public_numbers()
    
    # Convert to uncompressed format (0x04 prefix + X coordinate + Y coordinate)
    x_bytes = public_numbers.x.to_bytes(32, byteorder='big')
    y_bytes = public_numbers.y.to_bytes(32, byteorder='big')
    uncompressed_public_key = b'\x04' + x_bytes + y_bytes
    
    return private_key, uncompressed_public_key


def public_key_to_base64(public_key_bytes: bytes) -> str:
    """
    Convert public key bytes to base64 string for API submission.
    
    Args:
        public_key_bytes: Uncompressed public key (65 bytes)
    
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(public_key_bytes).decode('utf-8')


def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Input bytes
    
    Returns:
        SHA-256 hash bytes
    """
    return hashlib.sha256(data).digest()


def decrypt_credential_bundle(
    credential_bundle: str,
    ephemeral_private_key: ec.EllipticCurvePrivateKey
) -> str:
    """
    Decrypt the credential bundle using the ephemeral private key.
    
    The credential bundle is encrypted using ECDH (Elliptic Curve Diffie-Hellman)
    key exchange. We derive a shared secret and use it to decrypt the bundle.
    
    Args:
        credential_bundle: Base64 encoded encrypted credential bundle
        ephemeral_private_key: The ephemeral private key used to create the session
    
    Returns:
        Decrypted session private key (JWK format as JSON string)
    
    Note:
        This is a simplified implementation. The actual Zynk Labs implementation
        may use a different encryption scheme. You may need to adjust based on
        their actual encryption method.
    """
    try:
        # Decode the credential bundle
        encrypted_data = base64.b64decode(credential_bundle)
        
        # Extract components (this structure may vary based on Zynk's implementation)
        # Assuming format: ephemeral_public_key (65 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        if len(encrypted_data) < 77:  # 65 + 12 minimum
            raise ValueError("Invalid credential bundle format")
        
        # Extract ephemeral public key (65 bytes, uncompressed)
        ephemeral_pub_bytes = encrypted_data[:65]
        
        # Reconstruct the ephemeral public key
        if ephemeral_pub_bytes[0] != 0x04:
            raise ValueError("Invalid public key format - must be uncompressed")
        
        x = int.from_bytes(ephemeral_pub_bytes[1:33], byteorder='big')
        y = int.from_bytes(ephemeral_pub_bytes[33:65], byteorder='big')
        
        # Create public key from coordinates
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        ephemeral_public_key = public_numbers.public_key(default_backend())
        
        # Perform ECDH key exchange
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive encryption key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'credential_bundle',
            backend=default_backend()
        )
        encryption_key = hkdf.derive(shared_secret)
        
        # Extract nonce and ciphertext (assuming AES-GCM)
        nonce = encrypted_data[65:77]  # 12 bytes for GCM
        ciphertext_with_tag = encrypted_data[77:]
        
        # Decrypt using AES-GCM
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        
        # Parse the decrypted JSON
        session_key_jwk = json.loads(decrypted.decode('utf-8'))
        
        return json.dumps(session_key_jwk)
        
    except Exception as e:
        logger.error(f"Error decrypting credential bundle: {e}", exc_info=True)
        raise ValueError(f"Failed to decrypt credential bundle: {str(e)}")


def sign_payload_with_session_key(
    payload_to_sign: str,
    session_key_jwk: str
) -> str:
    """
    Sign a payload using the session private key.
    
    Args:
        payload_to_sign: JSON stringified payload to sign
        session_key_jwk: Session private key in JWK format (JSON string)
    
    Returns:
        Base64 encoded signature
    """
    try:
        # Parse the JWK
        key_data = json.loads(session_key_jwk)
        
        # Load the private key from JWK
        private_key = serialization.load_pem_private_key(
            json.dumps(key_data).encode(),
            password=None,
            backend=default_backend()
        )
        
        # For JWK format, we need to reconstruct the key differently
        # JWK format: {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..."}
        if key_data.get("kty") != "EC" or key_data.get("crv") != "P-256":
            raise ValueError("Unsupported key type - must be EC P-256")
        
        # Reconstruct private key from JWK components
        d = int.from_bytes(base64.urlsafe_b64decode(key_data["d"] + "=="), byteorder='big')
        x = int.from_bytes(base64.urlsafe_b64decode(key_data["x"] + "=="), byteorder='big')
        y = int.from_bytes(base64.urlsafe_b64decode(key_data["y"] + "=="), byteorder='big')
        
        # Create private key
        private_numbers = ec.EllipticCurvePrivateNumbers(
            private_value=d,
            public_numbers=ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        )
        private_key = private_numbers.private_key(default_backend())
        
        # Sign the payload
        signature = private_key.sign(
            payload_to_sign.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Encode signature as base64
        return base64.b64encode(signature).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Error signing payload: {e}", exc_info=True)
        raise ValueError(f"Failed to sign payload: {str(e)}")


def jwk_to_private_key(jwk_json: str) -> ec.EllipticCurvePrivateKey:
    """
    Convert JWK format private key to cryptography private key object.
    
    Args:
        jwk_json: JWK format key as JSON string
    
    Returns:
        EllipticCurvePrivateKey object
    """
    key_data = json.loads(jwk_json)
    
    if key_data.get("kty") != "EC" or key_data.get("crv") != "P-256":
        raise ValueError("Unsupported key type - must be EC P-256")
    
    # Decode JWK components
    d = int.from_bytes(
        base64.urlsafe_b64decode(key_data["d"] + "=="),
        byteorder='big'
    )
    x = int.from_bytes(
        base64.urlsafe_b64decode(key_data["x"] + "=="),
        byteorder='big'
    )
    y = int.from_bytes(
        base64.urlsafe_b64decode(key_data["y"] + "=="),
        byteorder='big'
    )
    
    # Create private key
    private_numbers = ec.EllipticCurvePrivateNumbers(
        private_value=d,
        public_numbers=ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    )
    
    return private_numbers.private_key(default_backend())

