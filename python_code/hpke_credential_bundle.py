"""
HPKE Credential Bundle Decryption - Python Implementation

This module provides functions to decrypt credential bundles using Hybrid Public Key
Encryption (HPKE) as specified in RFC 9180. It matches the exact logic of the
JavaScript/React implementation for Turnkey credential bundles.

Algorithm Details (HPKE Cipher Suite):
- KEM (Key Encapsulation Mechanism): DHKEM-P256-HKDF-SHA256
  - Uses P-256 elliptic curve (secp256r1)
  - Key derivation with HKDF-SHA256
- KDF (Key Derivation Function): HKDF-SHA256
- AEAD (Authenticated Encryption): AES-256-GCM
  - 256-bit AES encryption
  - Galois/Counter Mode for authentication

Bundle Format:
- Encoding: bs58check (Base58 with 4-byte checksum from double SHA-256)
- Structure: [EncappedPublicKey (33 bytes compressed) || Ciphertext (variable)]

Key Format Requirements:
- Ephemeral Private Key: 64-character hex string (32 bytes)
- Public Key (compressed): 66-character hex string (33 bytes)
- Public Key (uncompressed): 130-character hex string (65 bytes)
- Encapped Key in Bundle: 33-byte compressed format
- For HPKE operations: Keys are used in uncompressed format

AAD (Associated Authenticated Data) Construction:
- Format: EncappedPublicKey || ReceiverPublicKey
- Both keys in uncompressed format (65 bytes each)
- Total Length: 130 bytes

Info Parameter:
- Value: "turnkey_hpke" (UTF-8 encoded)
- Purpose: Domain separation for key derivation

Dependencies:
- pyhpke: Python HPKE implementation (RFC 9180)
- base58: Base58Check encoding/decoding
- cryptography: Elliptic curve operations (pyca/cryptography)

Installation:
    pip install pyhpke base58 cryptography

Usage Example:
    from hpke_credential_bundle import (
        generate_ephemeral_key_pair,
        decrypt_credential_bundle
    )
    
    # Generate ephemeral key pair (send publicKey to server)
    ephemeral_keys = generate_ephemeral_key_pair()
    print(f"Ephemeral Public Key: {ephemeral_keys['publicKey']}")
    print(f"Ephemeral Private Key: {ephemeral_keys['privateKey']}")
    
    # Decrypt credential bundle received from server
    decrypted = decrypt_credential_bundle(
        bundle_str=credential_bundle_from_server,
        ephemeral_private_key=ephemeral_keys['privateKey']
    )
    print(f"Decrypted Public Key: {decrypted['tempPublicKey']}")
    print(f"Decrypted Private Key: {decrypted['tempPrivateKey']}")

Author: Converted from JavaScript/React implementation
License: MIT
"""

import os
import base58
from typing import Tuple, Dict

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


def bytes_from_hex(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def is_hex_string(s: str) -> bool:
    """Check if a string is valid hexadecimal."""
    try:
        # Must have even length and all hex characters
        if len(s) % 2 != 0:
            return False
        int(s, 16)
        return True
    except ValueError:
        return False


def decode_bundle(bundle_str: str) -> bytes:
    """
    Decode a credential bundle from either hex or bs58check format.
    
    Args:
        bundle_str: Bundle string (hex or bs58check encoded)
    
    Returns:
        bytes: Decoded bundle bytes
    """
    # Check if it's a hex string
    if is_hex_string(bundle_str):
        return bytes.fromhex(bundle_str)
    
    # Otherwise, try bs58check
    return base58.b58decode_check(bundle_str)


def compress_public_key(uncompressed_key: bytes) -> bytes:
    """
    Compress an uncompressed P-256 public key (65 bytes) to compressed format (33 bytes).
    
    Uncompressed format: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    Compressed format: [0x02 or 0x03] || X (32 bytes) = 33 bytes
    """
    if len(uncompressed_key) != 65 or uncompressed_key[0] != 0x04:
        raise ValueError("Invalid uncompressed public key format")
    
    x = uncompressed_key[1:33]
    y = uncompressed_key[33:65]
    
    # Prefix is 0x02 if Y is even, 0x03 if Y is odd
    prefix = 0x02 if y[-1] % 2 == 0 else 0x03
    
    return bytes([prefix]) + x


def uncompress_public_key(compressed_key: bytes) -> bytes:
    """
    Uncompress a compressed P-256 public key (33 bytes) to uncompressed format (65 bytes).
    
    Uses the cryptography library to decode the point and get uncompressed representation.
    
    Compressed format: [0x02 or 0x03] || X (32 bytes) = 33 bytes
    Uncompressed format: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    """
    if len(compressed_key) != 33:
        raise ValueError(f"Invalid compressed public key length: {len(compressed_key)}")
    
    if compressed_key[0] not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed public key prefix: {hex(compressed_key[0])}")
    
    # Use cryptography library to decode the compressed point
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    
    # Load the compressed public key
    public_key = EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),  # P-256 curve
        compressed_key
    )
    
    # Get uncompressed representation (65 bytes with 0x04 prefix)
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return uncompressed


def generate_ephemeral_key_pair(compressed: bool = False) -> Dict[str, str]:
    """
    Generate an ephemeral P-256 key pair for HPKE decryption.
    
    Matches generate_keys_latest.js behavior - returns UNCOMPRESSED public key by default.
    
    Args:
        compressed: If True, return compressed public key (33 bytes, 66 hex chars)
                   If False (default), return uncompressed public key (65 bytes, 130 hex chars)
    
    Returns:
        dict: {
            'publicKey': public key hex string (uncompressed by default),
            'privateKey': private key (64-char hex, 32 bytes)
        }
    """
    # Generate P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Get private key as raw bytes (32 bytes), zero-padded like JS: padStart(64, '0')
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
    
    # Get public key in requested format
    if compressed:
        # Compressed format: 33 bytes (66 hex chars), prefix 02 or 03
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
    else:
        # Uncompressed format: 65 bytes (130 hex chars), prefix 04
        # This matches generate_keys_latest.js: keyPair.getPublic(false, 'hex')
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    return {
        'publicKey': bytes_to_hex(public_key_bytes),
        'privateKey': bytes_to_hex(private_key_bytes)
    }


def derive_public_key_from_private(private_key_hex: str) -> Tuple[bytes, bytes]:
    """
    Derive public key from private key.
    
    Args:
        private_key_hex: 64-character hex string (32 bytes)
    
    Returns:
        Tuple of (compressed_public_key, uncompressed_public_key)
    """
    private_key_bytes = bytes_from_hex(private_key_hex)
    
    # Create private key object
    private_value = int.from_bytes(private_key_bytes, byteorder='big')
    private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())
    
    # Get public key in both formats
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
    """
    Decrypt a credential bundle using HPKE.
    
    Args:
        bundle_str: Credential bundle (hex or bs58check encoded)
        ephemeral_private_key: 64-character hex string (32 bytes)
    
    Returns:
        dict: {
            'tempPublicKey': compressed public key of decrypted key (66-char hex),
            'tempPrivateKey': decrypted private key (64-char hex)
        }
    
    Raises:
        ValueError: If bundle is invalid or decryption fails
    """
    # 1. Decode bundle (auto-detect format: hex or bs58check)
    bundle_bytes = decode_bundle(bundle_str)
    
    # 2. Detect encapped key format (compressed vs uncompressed)
    first_byte = bundle_bytes[0]
    
    if first_byte == 0x04:
        # Uncompressed format: first 65 bytes are the encapped key
        if len(bundle_bytes) < 65:
            raise ValueError(f"Bundle too small for uncompressed key: {len(bundle_bytes)} bytes")
        enc = bundle_bytes[:65]  # Already uncompressed
        ciphertext = bundle_bytes[65:]
    elif first_byte in (0x02, 0x03):
        # Compressed format: first 33 bytes are the encapped key
        if len(bundle_bytes) < 33:
            raise ValueError(f"Bundle too small for compressed key: {len(bundle_bytes)} bytes")
        compressed_encapped_key = bundle_bytes[:33]
        ciphertext = bundle_bytes[33:]
        # Uncompress the encapped key
        enc = uncompress_public_key(compressed_encapped_key)
    else:
        raise ValueError(f"Invalid encapped key prefix: {hex(first_byte)}")
    
    # Validate ciphertext
    if len(ciphertext) < 16:
        raise ValueError(f"Ciphertext too small: {len(ciphertext)} bytes")
    
    # 4. Build HPKE cipher suite
    # Note: AES256_GCM for AES-256-GCM as per the JS implementation
    suite = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM
    )
    
    # 5. Derive receiver public key from ephemeral private key
    _, receiver_public_key = derive_public_key_from_private(ephemeral_private_key)
    
    # 6. Import recipient private key using pyca/cryptography
    private_key_bytes = bytes_from_hex(ephemeral_private_key)
    private_value = int.from_bytes(private_key_bytes, byteorder='big')
    pyca_private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())
    
    # Convert to pyhpke KEMKey
    recipient_key = KEMKey.from_pyca_cryptography_key(pyca_private_key)
    
    # 7. Construct AAD: EncappedPublicKey || ReceiverPublicKey (both uncompressed, 130 bytes total)
    aad = enc + receiver_public_key
    
    # 8. Create recipient context with info parameter
    info = b"turnkey_hpke"
    
    recipient_ctx = suite.create_recipient_context(
        enc=enc,
        skr=recipient_key,
        info=info
    )
    
    # 9. Decrypt ciphertext
    plaintext = recipient_ctx.open(ciphertext, aad)
    
    # 10. Extract private key from plaintext
    private_key_hex = bytes_to_hex(plaintext)
    
    # 11. Generate corresponding public key
    temp_compressed, _ = derive_public_key_from_private(private_key_hex)
    temp_public_key = bytes_to_hex(temp_compressed)
    temp_private_key = private_key_hex
    
    return {
        'tempPublicKey': temp_public_key,
        'tempPrivateKey': temp_private_key
    }


def encrypt_credential_bundle(
    private_key_to_encrypt: str,
    recipient_public_key_hex: str
) -> str:
    """
    Encrypt a private key into a credential bundle using HPKE.
    
    This function is useful for testing the decryption function.
    
    Args:
        private_key_to_encrypt: Private key to encrypt (64-char hex)
        recipient_public_key_hex: Recipient's public key (compressed 66-char or uncompressed 130-char hex)
    
    Returns:
        bs58check encoded bundle string
    """
    # Build HPKE cipher suite
    suite = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM
    )
    
    # Import recipient public key (handle both compressed and uncompressed)
    recipient_key_bytes = bytes_from_hex(recipient_public_key_hex)
    
    if len(recipient_key_bytes) == 33:
        # Compressed format - uncompress it
        uncompressed_recipient_key = uncompress_public_key(recipient_key_bytes)
    elif len(recipient_key_bytes) == 65 and recipient_key_bytes[0] == 0x04:
        # Already uncompressed
        uncompressed_recipient_key = recipient_key_bytes
    else:
        raise ValueError(f"Invalid recipient public key format. Length: {len(recipient_key_bytes)}")
    
    # Load recipient public key
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    pyca_public_key = EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        uncompressed_recipient_key
    )
    
    recipient_key = KEMKey.from_pyca_cryptography_key(pyca_public_key)
    
    # Create sender context
    info = b"turnkey_hpke"
    enc, sender_ctx = suite.create_sender_context(recipient_key, info=info)
    
    # Construct AAD: EncappedPublicKey || ReceiverPublicKey (both uncompressed)
    aad = enc + uncompressed_recipient_key
    
    # Encrypt the private key
    plaintext = bytes_from_hex(private_key_to_encrypt)
    ciphertext = sender_ctx.seal(plaintext, aad)
    
    # Compress the encapped key for the bundle
    compressed_enc = compress_public_key(enc)
    
    # Construct bundle: compressed encapped key (33 bytes) || ciphertext
    bundle_bytes = compressed_enc + ciphertext
    
    # Encode with bs58check
    bundle_str = base58.b58encode_check(bundle_bytes).decode('ascii')
    
    return bundle_str


# ============================================================================
# CLI Interface - Matches decrypt_bundle.js behavior
# ============================================================================

def decrypt_bundle_cli(bundle_str: str, ephemeral_private_key: str, verbose: bool = True) -> Dict[str, str]:
    """
    Decrypt a credential bundle with verbose logging matching decrypt_bundle.js.
    
    Args:
        bundle_str: Credential bundle (hex or bs58check encoded)
        ephemeral_private_key: 64-character hex string (32 bytes)
        verbose: Whether to print debug information
    
    Returns:
        dict: {
            'tempPublicKey': compressed public key of decrypted key (66-char hex),
            'tempPrivateKey': decrypted private key (64-char hex, zero-padded)
        }
    """
    # 1. Decode bundle (auto-detect format: hex or bs58check)
    bundle_bytes = decode_bundle(bundle_str)
    
    if verbose:
        encoding = "hex" if is_hex_string(bundle_str) else "bs58check"
        print(f"Bundle encoding detected: {encoding}")
    
    if verbose:
        print(f"Bundle decoded, length: {len(bundle_bytes)} bytes")
    
    # 2. Detect encapped key format (compressed vs uncompressed)
    first_byte = bundle_bytes[0]
    
    if first_byte == 0x04:
        # Uncompressed format: first 65 bytes are the encapped key
        if len(bundle_bytes) < 65:
            raise ValueError(f"Bundle too small for uncompressed key: {len(bundle_bytes)} bytes")
        
        enc = bundle_bytes[:65]  # Already uncompressed
        ciphertext = bundle_bytes[65:]
        
        if verbose:
            print(f"Encapped key format: uncompressed (65 bytes)")
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            
    elif first_byte in (0x02, 0x03):
        # Compressed format: first 33 bytes are the encapped key
        if len(bundle_bytes) < 33:
            raise ValueError(f"Bundle too small for compressed key: {len(bundle_bytes)} bytes")
        
        compressed_encapped_key = bundle_bytes[:33]
        ciphertext = bundle_bytes[33:]
        
        if verbose:
            print(f"Encapped key format: compressed (33 bytes)")
            print(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Uncompress the encapped key
        enc = uncompress_public_key(compressed_encapped_key)
        
        if verbose:
            print(f"Encapped key (uncompressed): {len(enc)} bytes")
    else:
        raise ValueError(f"Invalid encapped key prefix: {hex(first_byte)}. Expected 0x02, 0x03 (compressed) or 0x04 (uncompressed)")
    
    # Validate ciphertext
    if len(ciphertext) < 16:
        raise ValueError(f"Ciphertext too small: {len(ciphertext)} bytes. Expected at least 16 bytes (GCM tag)")
    
    # 3. Build HPKE cipher suite
    suite = CipherSuite.new(
        KEMId.DHKEM_P256_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM
    )
    
    # 4. Derive receiver public key from ephemeral private key
    _, receiver_public_key = derive_public_key_from_private(ephemeral_private_key)
    
    if verbose:
        print(f"Receiver public key (uncompressed): {len(receiver_public_key)} bytes")
    
    # 5. Import recipient private key
    private_key_bytes = bytes_from_hex(ephemeral_private_key)
    private_value = int.from_bytes(private_key_bytes, byteorder='big')
    pyca_private_key = ec.derive_private_key(private_value, ec.SECP256R1(), default_backend())
    recipient_key = KEMKey.from_pyca_cryptography_key(pyca_private_key)
    
    # 6. Construct AAD: EncappedPublicKey || ReceiverPublicKey
    aad = enc + receiver_public_key
    
    if verbose:
        print(f"AAD length: {len(aad)} bytes")
    
    # 7. Create recipient context
    info = b"turnkey_hpke"
    
    recipient_ctx = suite.create_recipient_context(
        enc=enc,
        skr=recipient_key,
        info=info
    )
    
    # 8. Decrypt ciphertext
    plaintext = recipient_ctx.open(ciphertext, aad)
    
    # 9. Extract private key (with zero-padding to match JS behavior)
    private_key_hex = bytes_to_hex(plaintext).zfill(64)  # padStart(64, '0')
    
    # 10. Generate corresponding public key
    temp_compressed, _ = derive_public_key_from_private(private_key_hex)
    temp_public_key = bytes_to_hex(temp_compressed)
    temp_private_key = private_key_hex
    
    return {
        'tempPublicKey': temp_public_key,
        'tempPrivateKey': temp_private_key
    }


def main():
    """
    Main CLI entry point - matches decrypt_bundle.js and generate_keys_latest.js behavior.
    
    Usage:
        Generate keys:  python hpke_credential_bundle.py --generate-keys
        Decrypt bundle: python hpke_credential_bundle.py <credential_bundle>
        Run tests:      python hpke_credential_bundle.py --test
    
    For decryption:
        Reads ephemeral private key from: ephemeral_private.hex
        Saves results to: session_private_key.hex, session_public_key.hex
    """
    import sys
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("HPKE Credential Bundle - Python Implementation")
        print("")
        print("Usage:")
        print("  Generate keys:  python hpke_credential_bundle.py --generate-keys")
        print("  Decrypt bundle: python hpke_credential_bundle.py <credential_bundle>")
        print("  Run tests:      python hpke_credential_bundle.py --test")
        print("")
        print("Key Generation (matches generate_keys_latest.js):")
        print("  Creates ephemeral_private.hex and ephemeral_public.hex")
        print("  Public key is UNCOMPRESSED format (130 hex chars, starts with 04)")
        print("")
        print("Decryption:")
        print("  Reads private key from ephemeral_private.hex")
        print("  Accepts both hex and bs58check encoded bundles")
        print("  Accepts both compressed and uncompressed encapped keys")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    # Key generation mode (matches generate_keys_latest.js)
    if arg == '--generate-keys' or arg == '-g':
        keys = generate_ephemeral_key_pair(compressed=False)  # Uncompressed like JS
        
        # Save to files (matches JS behavior)
        with open('ephemeral_private.hex', 'w') as f:
            f.write(keys['privateKey'])
        
        with open('ephemeral_public.hex', 'w') as f:
            f.write(keys['publicKey'])
        
        print("Private key saved to: ephemeral_private.hex")
        print("Public key saved to: ephemeral_public.hex")
        print("")
        print(f"Private key length: {len(keys['privateKey'])} hex chars")
        print(f"Public key length: {len(keys['publicKey'])} hex chars")
        print(f"Public key prefix: {keys['publicKey'][:2]}")
        print("")
        print("Use this public key in start-session API:")
        print(keys['publicKey'])
        return
    
    # Test mode
    if arg == '--test' or arg == '-t':
        run_all_tests()
        return
    
    # Decrypt mode
    bundle_str = arg
    
    try:
        # Read ephemeral private key from file
        with open('ephemeral_private.hex', 'r') as f:
            ephemeral_private_key = f.read().strip()
        
        print(f"Loaded private key from: ephemeral_private.hex")
        print(f"Private key length: {len(ephemeral_private_key)} hex chars\n")
        
        # Decrypt the bundle
        result = decrypt_bundle_cli(bundle_str, ephemeral_private_key, verbose=True)
        
        print("\n=== Decryption Successful ===")
        print(f"Session Public Key: {result['tempPublicKey']}")
        print(f"Session Private Key: {result['tempPrivateKey']}")
        
        # Save results to files
        with open('session_private_key.hex', 'w') as f:
            f.write(result['tempPrivateKey'])
        
        with open('session_public_key.hex', 'w') as f:
            f.write(result['tempPublicKey'])
        
        print("\nSaved to: session_private_key.hex, session_public_key.hex")
        
    except FileNotFoundError:
        print("\n❌ Error: ephemeral_private.hex not found")
        print("Please run: python hpke_credential_bundle.py --generate-keys")
        sys.exit(1)
    except Exception as error:
        print(f"\n❌ Decryption failed: {error}")
        sys.exit(1)


# ============================================================================
# Test functions
# ============================================================================

def test_key_generation():
    """Test ephemeral key pair generation."""
    print("=" * 60)
    print("Testing Key Generation")
    print("=" * 60)
    
    # Test uncompressed (default, matches generate_keys_latest.js)
    keys = generate_ephemeral_key_pair(compressed=False)
    
    print(f"Public Key (uncompressed): {keys['publicKey']}")
    print(f"Public Key length: {len(keys['publicKey'])} chars ({len(keys['publicKey'])//2} bytes)")
    print(f"Public Key prefix: {keys['publicKey'][:2]}")
    print(f"Private Key: {keys['privateKey']}")
    print(f"Private Key length: {len(keys['privateKey'])} chars ({len(keys['privateKey'])//2} bytes)")
    
    # Verify uncompressed format
    assert len(keys['publicKey']) == 130, "Uncompressed public key should be 130 hex chars"
    assert keys['publicKey'].startswith('04'), "Uncompressed public key should start with 04"
    assert len(keys['privateKey']) == 64, "Private key should be 64 hex chars"
    
    # Verify we can derive public key from private
    compressed, uncompressed = derive_public_key_from_private(keys['privateKey'])
    assert bytes_to_hex(uncompressed) == keys['publicKey'], "Public key derivation mismatch"
    
    # Test compressed format
    keys_compressed = generate_ephemeral_key_pair(compressed=True)
    assert len(keys_compressed['publicKey']) == 66, "Compressed public key should be 66 hex chars"
    assert keys_compressed['publicKey'][:2] in ('02', '03'), "Compressed public key should start with 02 or 03"
    
    print("✅ Key generation test passed!")
    return keys


def test_key_compression():
    """Test public key compression/decompression."""
    print("\n" + "=" * 60)
    print("Testing Key Compression/Decompression")
    print("=" * 60)
    
    keys = generate_ephemeral_key_pair()
    
    # Get compressed and uncompressed versions
    compressed, uncompressed = derive_public_key_from_private(keys['privateKey'])
    
    print(f"Compressed: {bytes_to_hex(compressed)} ({len(compressed)} bytes)")
    print(f"Uncompressed: {bytes_to_hex(uncompressed)} ({len(uncompressed)} bytes)")
    
    # Test uncompress
    uncompressed_test = uncompress_public_key(compressed)
    assert uncompressed_test == uncompressed, "Uncompress failed"
    
    # Test compress
    compressed_test = compress_public_key(uncompressed)
    assert compressed_test == compressed, "Compress failed"
    
    print("✅ Key compression test passed!")


def test_encryption_decryption():
    """Test full encryption/decryption cycle."""
    print("\n" + "=" * 60)
    print("Testing Encryption/Decryption Cycle")
    print("=" * 60)
    
    # 1. Generate recipient (ephemeral) key pair
    recipient_keys = generate_ephemeral_key_pair()
    print(f"Recipient Public Key: {recipient_keys['publicKey']}")
    print(f"Recipient Private Key: {recipient_keys['privateKey']}")
    
    # 2. Generate a random private key to encrypt (simulating the credential)
    test_private_key = os.urandom(32).hex()
    print(f"\nOriginal Private Key to encrypt: {test_private_key}")
    
    # 3. Encrypt
    bundle_str = encrypt_credential_bundle(
        test_private_key,
        recipient_keys['publicKey']
    )
    print(f"\nEncrypted Bundle (bs58check): {bundle_str}")
    print(f"Bundle length: {len(bundle_str)} characters")
    
    # 4. Decrypt
    decrypted = decrypt_credential_bundle(
        bundle_str,
        recipient_keys['privateKey']
    )
    print(f"\nDecrypted Private Key: {decrypted['tempPrivateKey']}")
    print(f"Decrypted Public Key: {decrypted['tempPublicKey']}")
    
    # 5. Verify
    assert decrypted['tempPrivateKey'] == test_private_key, "Private key mismatch!"
    
    # Verify the public key matches
    expected_compressed, _ = derive_public_key_from_private(test_private_key)
    assert decrypted['tempPublicKey'] == bytes_to_hex(expected_compressed), "Public key mismatch!"
    
    print("\n✅ Encryption/Decryption test passed!")


def test_bundle_format():
    """Test bundle format parsing."""
    print("\n" + "=" * 60)
    print("Testing Bundle Format")
    print("=" * 60)
    
    # Generate test data
    recipient_keys = generate_ephemeral_key_pair()
    test_private_key = os.urandom(32).hex()
    
    bundle_str = encrypt_credential_bundle(
        test_private_key,
        recipient_keys['publicKey']
    )
    
    # Decode and inspect
    bundle_bytes = base58.b58decode_check(bundle_str)
    
    print(f"Total bundle size: {len(bundle_bytes)} bytes")
    print(f"Encapped key (compressed): {bytes_to_hex(bundle_bytes[:33])} (33 bytes)")
    print(f"Ciphertext: {bytes_to_hex(bundle_bytes[33:])} ({len(bundle_bytes[33:])} bytes)")
    
    # Verify structure
    assert len(bundle_bytes) >= 33, "Bundle too small"
    assert bundle_bytes[0] in (0x02, 0x03), "Invalid compressed key prefix"
    
    print("✅ Bundle format test passed!")


def run_all_tests():
    """Run all tests."""
    print("\n" + "#" * 60)
    print("# HPKE Credential Bundle - Python Implementation Tests")
    print("#" * 60)
    
    test_key_generation()
    test_key_compression()
    test_encryption_decryption()
    test_bundle_format()
    
    print("\n" + "#" * 60)
    print("# ALL TESTS PASSED! ✅")
    print("#" * 60)


if __name__ == "__main__":
    import sys
    
    # If command line argument provided, run CLI mode
    # Otherwise, run tests
    if len(sys.argv) > 1 and sys.argv[1] != '--test':
        main()
    else:
        run_all_tests()
