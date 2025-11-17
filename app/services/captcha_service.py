"""
CAPTCHA Service

Generates and validates CAPTCHA codes for registration and other protected endpoints.
Uses in-memory storage with TTL (time-to-live) for security.
"""

import random
import string
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)


class CaptchaService:
    """Service for managing CAPTCHA generation and validation"""
    
    CAPTCHA_LENGTH = 5  # 5-character CAPTCHA code
    CAPTCHA_EXPIRY_MINUTES = 10  # CAPTCHA expires after 10 minutes
    CLEANUP_INTERVAL_SECONDS = 300  # Clean up expired CAPTCHAs every 5 minutes
    
    def __init__(self):
        # In-memory storage: {captcha_id: {"code": str, "expires_at": datetime, "attempts": int}}
        self._captcha_store: Dict[str, Dict] = {}
        self._last_cleanup = datetime.now(timezone.utc)
        
    def _generate_code(self) -> str:
        """Generate a random CAPTCHA code"""
        # Use uppercase letters and numbers, excluding confusing characters (0, O, I, 1)
        chars = string.ascii_uppercase.replace('O', '').replace('I', '') + string.digits.replace('0', '').replace('1', '')
        return ''.join(random.choice(chars) for _ in range(self.CAPTCHA_LENGTH))
    
    def _cleanup_expired(self):
        """Remove expired CAPTCHA codes from memory"""
        now = datetime.now(timezone.utc)
        # Only cleanup periodically to avoid performance issues
        if (now - self._last_cleanup).total_seconds() < self.CLEANUP_INTERVAL_SECONDS:
            return
        
        expired_ids = [
            captcha_id for captcha_id, data in self._captcha_store.items()
            if data["expires_at"] < now
        ]
        
        for captcha_id in expired_ids:
            del self._captcha_store[captcha_id]
        
        self._last_cleanup = now
        if expired_ids:
            logger.debug(f"[CAPTCHA] Cleaned up {len(expired_ids)} expired CAPTCHAs")
    
    def generate_captcha(self, session_id: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate a new CAPTCHA code.
        
        Args:
            session_id: Optional session identifier (e.g., from request)
            
        Returns:
            Tuple of (captcha_id, captcha_code)
        """
        # Cleanup expired CAPTCHAs periodically
        self._cleanup_expired()
        
        # Generate CAPTCHA code
        captcha_code = self._generate_code()
        captcha_id = self._generate_id(session_id)
        
        # Store with expiry
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.CAPTCHA_EXPIRY_MINUTES)
        self._captcha_store[captcha_id] = {
            "code": captcha_code,
            "expires_at": expires_at,
            "attempts": 0,
            "created_at": datetime.now(timezone.utc),
        }
        
        logger.info(f"[CAPTCHA] Generated CAPTCHA {captcha_id}: {captcha_code} (expires at {expires_at.isoformat()})")
        
        return captcha_id, captcha_code
    
    def _generate_id(self, session_id: Optional[str] = None) -> str:
        """Generate a unique CAPTCHA ID"""
        if session_id:
            # Use session-based ID for better tracking
            return f"{session_id}_{uuid.uuid4().hex[:8]}"
        return uuid.uuid4().hex
    
    def validate_captcha(self, captcha_id: str, user_input: str) -> Tuple[bool, str]:
        """
        Validate a CAPTCHA code.
        
        Args:
            captcha_id: CAPTCHA identifier
            user_input: User's input code
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Cleanup expired CAPTCHAs
        self._cleanup_expired()
        
        # Normalize user input (uppercase, strip whitespace)
        user_input = user_input.strip().upper()
        
        # Check if CAPTCHA exists
        if captcha_id not in self._captcha_store:
            logger.warning(f"[CAPTCHA] Invalid CAPTCHA ID: {captcha_id}")
            return False, "Invalid or expired CAPTCHA. Please request a new one."
        
        captcha_data = self._captcha_store[captcha_id]
        
        # Check if expired
        if datetime.now(timezone.utc) > captcha_data["expires_at"]:
            del self._captcha_store[captcha_id]
            logger.warning(f"[CAPTCHA] Expired CAPTCHA: {captcha_id}")
            return False, "CAPTCHA expired. Please request a new one."
        
        # Increment attempts
        captcha_data["attempts"] += 1
        
        # Validate code (case-insensitive)
        stored_code = captcha_data["code"].upper()
        is_valid = stored_code == user_input
        
        if is_valid:
            # Remove CAPTCHA after successful validation (one-time use)
            del self._captcha_store[captcha_id]
            logger.info(f"[CAPTCHA] Validated CAPTCHA {captcha_id} successfully")
            return True, ""
        else:
            # Keep CAPTCHA for retry, but log attempt
            logger.warning(f"[CAPTCHA] Invalid CAPTCHA attempt for {captcha_id} (attempt {captcha_data['attempts']})")
            return False, "Invalid CAPTCHA code. Please try again."
    
    def get_captcha_info(self, captcha_id: str) -> Optional[Dict]:
        """Get CAPTCHA information without validating (for display)"""
        self._cleanup_expired()
        
        if captcha_id not in self._captcha_store:
            return None
        
        captcha_data = self._captcha_store[captcha_id]
        
        # Check if expired
        if datetime.now(timezone.utc) > captcha_data["expires_at"]:
            del self._captcha_store[captcha_id]
            return None
        
        return {
            "code": captcha_data["code"],  # Return code for testing/display
            "expires_at": captcha_data["expires_at"].isoformat(),
            "attempts": captcha_data["attempts"],
        }


# Global instance
captcha_service = CaptchaService()

