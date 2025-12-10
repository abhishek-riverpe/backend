"""
CAPTCHA Service

Generates and validates CAPTCHA codes for registration and other protected endpoints.
Uses in-memory storage with TTL (time-to-live) for security.
Generates image-based CAPTCHAs with noise and distortion for better security.
"""

import random
import string
import logging
import uuid
import base64
import io
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple
from PIL import Image, ImageDraw, ImageFont, ImageFilter

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
        # Use mixed case letters and numbers for stronger security, excluding confusing characters
        chars = (string.ascii_uppercase.replace('O', '').replace('I', '') +
                string.ascii_lowercase.replace('o', '').replace('i', '').replace('l', '') +
                string.digits.replace('0', '').replace('1', ''))
        return ''.join(random.choice(chars) for _ in range(self.CAPTCHA_LENGTH))
    
    def _generate_captcha_image(self, code: str) -> str:
        """
        Generate a CAPTCHA image with noise and distortion.
        
        Args:
            code: The CAPTCHA code to render
            
        Returns:
            Base64-encoded PNG image string
        """
        # Image dimensions
        width, height = 200, 80
        background_color = (240, 240, 240)  # Light gray background
        text_color = (60, 60, 60)  # Dark gray text
        
        # Create image
        img = Image.new('RGB', (width, height), background_color)
        draw = ImageDraw.Draw(img)
        
        # Try to use a bold font, fallback to default if not available
        font_size = 40
        font = None
        
        # Try different font paths (Linux, macOS, Windows)
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/arial.ttf",
        ]
        
        for font_path in font_paths:
            try:
                font = ImageFont.truetype(font_path, font_size)
                break
            except (OSError, IOError):
                continue
        
        # Fallback to default font if none found
        if font is None:
            font = ImageFont.load_default()
        
        # Calculate text position (centered)
        bbox = draw.textbbox((0, 0), code, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (width - text_width) // 2
        y = (height - text_height) // 2 - 5
        
        # Draw text with slight random positioning for each character
        char_width = text_width // len(code)
        for i, char in enumerate(code):
            # Slight random offset for each character
            offset_x = random.randint(-3, 3)
            offset_y = random.randint(-2, 2)
            char_x = x + (i * char_width) + offset_x
            char_y = y + offset_y
            
            # Draw character
            draw.text((char_x, char_y), char, fill=text_color, font=font)
        
        # Add noise (speckles) - similar to the image shown
        noise_count = random.randint(800, 1200)
        for _ in range(noise_count):
            x_noise = random.randint(0, width - 1)
            y_noise = random.randint(0, height - 1)
            # Random dark or light pixels
            noise_color = random.choice([
                (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100)),  # Dark
                (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))  # Light
            ])
            draw.point((x_noise, y_noise), fill=noise_color)
        
        # Add random lines to make it harder to read
        line_count = random.randint(3, 6)
        for _ in range(line_count):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            line_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
            draw.line([(x1, y1), (x2, y2)], fill=line_color, width=1)
        
        # Apply slight blur/filter for additional distortion
        img = img.filter(ImageFilter.SMOOTH_MORE)
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return img_str
    
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
    
    def generate_captcha(self, session_id: Optional[str] = None) -> Tuple[str, str, str]:
        """
        Generate a new CAPTCHA code with image.
        
        Args:
            session_id: Optional session identifier (e.g., from request)
            
        Returns:
            Tuple of (captcha_id, captcha_code, captcha_image_base64)
        """
        # Cleanup expired CAPTCHAs periodically
        self._cleanup_expired()
        
        # Generate CAPTCHA code
        captcha_code = self._generate_code()
        captcha_id = self._generate_id(session_id)
        
        # Generate CAPTCHA image
        captcha_image = self._generate_captcha_image(captcha_code)
        
        # Store with expiry
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.CAPTCHA_EXPIRY_MINUTES)
        self._captcha_store[captcha_id] = {
            "code": captcha_code,
            "expires_at": expires_at,
            "attempts": 0,
            "created_at": datetime.now(timezone.utc),
        }
        
        logger.info(f"[CAPTCHA] Generated CAPTCHA {captcha_id}: {captcha_code} (expires at {expires_at.isoformat()})")
        
        return captcha_id, captcha_code, captcha_image
    
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
        
        # Normalize user input (strip whitespace only - case-sensitive for security)
        user_input = user_input.strip()

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

        # Check if CAPTCHA was already validated recently
        if captcha_data.get("validated", False):
            validated_at = captcha_data.get("validated_at")
            if validated_at and (datetime.now(timezone.utc) - validated_at).total_seconds() < 300:  # 5 minutes
                logger.info(f"[CAPTCHA] Reusing previously validated CAPTCHA {captcha_id}")
                return True, ""
            else:
                # Validation expired, remove CAPTCHA
                del self._captcha_store[captcha_id]
                logger.warning(f"[CAPTCHA] Previously validated CAPTCHA expired: {captcha_id}")
                return False, "CAPTCHA validation expired. Please request a new one."

        # Validate code (case-sensitive for stronger security)
        stored_code = captcha_data["code"]
        is_valid = stored_code == user_input

        if is_valid:
            # Mark CAPTCHA as validated but keep it for a short time (5 minutes)
            # This allows retrying signup if it fails for non-CAPTCHA reasons
            captcha_data["validated"] = True
            captcha_data["validated_at"] = datetime.now(timezone.utc)
            captcha_data["expires_at"] = datetime.now(timezone.utc) + timedelta(minutes=5)  # Extend expiry
            logger.info(f"[CAPTCHA] Validated CAPTCHA {captcha_id} successfully (reusable for 5 min)")
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

