"""
Wallet Cryptographic Utilities

Handles P-256 key pair generation, credential decryption, and payload signing
for Zynk Labs wallet creation flow.
"""

import base64
import json
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
import os

logger = logging.getLogger(__name__)


def generate_p256_key_pair():
    """
    Generate an ECDSA P-256 (secp256r1) private and public key pair.
    
    Returns:
        tuple: (private_key_pem, public_key_base64)
            - private_key_pem: PEM-encoded private key (string)
            - public_key_base64: Base64-encoded uncompressed public key (string)
    """
    try:
        # Generate P-256 key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Serialize public key to uncompressed format (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Encode to Base64
        public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')
        
        return private_key_pem, public_key_base64
    
    except Exception as e:
        logger.error(f"Error generating P-256 key pair: {str(e)}", exc_info=True)
        raise


def public_key_to_base64(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Convert a public key to uncompressed Base64 format.
    
    Args:
        public_key: EllipticCurvePublicKey object
        
    Returns:
        Base64-encoded uncompressed public key string
    """
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return base64.b64encode(public_key_bytes).decode('utf-8')


def decrypt_credential_bundle(credential_bundle: str, private_key_pem: str) -> dict:
    """
    Decrypt a credential bundle using the ephemeral private key.
    
    The credential bundle is encrypted by Zynk Labs using the ephemeral public key
    sent during session creation. This function decrypts it to extract the session key.
    
    Args:
        credential_bundle: Base64-encoded encrypted credential bundle from Zynk
        private_key_pem: PEM-encoded ephemeral private key
        
    Returns:
        dict: Decrypted credential data containing session key in JWK format
    """
    try:
        # Load private key from PEM
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode credential bundle
        encrypted_data = base64.b64decode(credential_bundle)
        
        # Extract ephemeral public key and encrypted payload
        # Format: [ephemeral_public_key (65 bytes)][iv (16 bytes)][encrypted_data][tag (16 bytes)]
        if len(encrypted_data) < 65 + 16 + 16:
            raise ValueError("Invalid credential bundle format")
        
        ephemeral_public_key_bytes = encrypted_data[:65]
        iv = encrypted_data[65:65+16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[65+16:-16]
        
        # Load ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            ephemeral_public_key_bytes,
            default_backend()
        )
        
        # Perform ECDH to derive shared secret
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive AES key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'wallet-credential-encryption',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Decrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Parse JSON
        credential_data = json.loads(decrypted_data.decode('utf-8'))
        
        return credential_data
    
    except Exception as e:
        logger.error(f"Error decrypting credential bundle: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to decrypt credential bundle: {str(e)}")


def sign_payload_with_session_key(payload_to_sign: str, session_key_jwk: str) -> str:
    """
    Sign a payload using the session private key (from JWK).
    
    Args:
        payload_to_sign: String payload to sign
        session_key_jwk: Session private key in JWK format (JSON string)
        
    Returns:
        Base64-encoded signature string
    """
    try:
        # Parse JWK
        jwk_data = json.loads(session_key_jwk)
        
        # Extract private key components from JWK
        if jwk_data.get('kty') != 'EC' or jwk_data.get('crv') != 'P-256':
            raise ValueError("JWK must be P-256 ECDSA key")
        
        # Reconstruct private key from JWK
        # Note: This is a simplified version. Full JWK parsing would require
        # handling 'd' (private key) and 'x', 'y' (public key coordinates)
        d_bytes = base64.urlsafe_b64decode(jwk_data['d'] + '==')
        x_bytes = base64.urlsafe_b64decode(jwk_data['x'] + '==')
        y_bytes = base64.urlsafe_b64decode(jwk_data['y'] + '==')
        
        # Create private key from private scalar
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateNumbers
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
        
        private_value = int.from_bytes(d_bytes, 'big')
        public_numbers = EllipticCurvePublicNumbers(
            x=int.from_bytes(x_bytes, 'big'),
            y=int.from_bytes(y_bytes, 'big'),
            curve=ec.SECP256R1()
        )
        private_numbers = EllipticCurvePrivateNumbers(
            private_value=private_value,
            public_numbers=public_numbers
        )
        private_key = private_numbers.private_key(default_backend())
        
        # Sign payload
        signature = private_key.sign(
            payload_to_sign.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Encode signature (DER format)
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        
        return signature_base64
    
    except Exception as e:
        logger.error(f"Error signing payload: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to sign payload: {str(e)}")

