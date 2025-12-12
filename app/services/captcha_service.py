import random
import string
import uuid
import base64
import io
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple
from PIL import Image, ImageDraw, ImageFont, ImageFilter # type: ignore


class CaptchaService:
    
    CAPTCHA_LENGTH = 5
    CAPTCHA_EXPIRY_MINUTES = 10
    CLEANUP_INTERVAL_SECONDS = 300
    
    def __init__(self):
        self._captcha_store: Dict[str, Dict] = {}
        self._last_cleanup = datetime.now(timezone.utc)
        
    def _generate_code(self) -> str:
        chars = (string.ascii_uppercase.replace('O', '').replace('I', '') +
                string.ascii_lowercase.replace('o', '').replace('i', '').replace('l', '') +
                string.digits.replace('0', '').replace('1', ''))
        return ''.join(random.choice(chars) for _ in range(self.CAPTCHA_LENGTH))
    
    def _generate_captcha_image(self, code: str) -> str:
        width, height = 200, 80
        background_color = (240, 240, 240)
        text_color = (60, 60, 60)
        
        img = Image.new('RGB', (width, height), background_color)
        draw = ImageDraw.Draw(img)
        
        font_size = 40
        font = None
        
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
            except:
                continue
        
        if font is None:
            font = ImageFont.load_default()
        
        bbox = draw.textbbox((0, 0), code, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (width - text_width) // 2
        y = (height - text_height) // 2 - 5
        
        char_width = text_width // len(code)
        for i, char in enumerate(code):
            offset_x = random.randint(-3, 3)
            offset_y = random.randint(-2, 2)
            char_x = x + (i * char_width) + offset_x
            char_y = y + offset_y
            
            draw.text((char_x, char_y), char, fill=text_color, font=font)
        
        noise_count = random.randint(800, 1200)
        for _ in range(noise_count):
            x_noise = random.randint(0, width - 1)
            y_noise = random.randint(0, height - 1)
            noise_color = random.choice([
                (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100)),
                (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))
            ])
            draw.point((x_noise, y_noise), fill=noise_color)
        
        line_count = random.randint(3, 6)
        for _ in range(line_count):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            line_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
            draw.line([(x1, y1), (x2, y2)], fill=line_color, width=1)
        
        img = img.filter(ImageFilter.SMOOTH_MORE)
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return img_str
    
    def _cleanup_expired(self):
        now = datetime.now(timezone.utc)
        if (now - self._last_cleanup).total_seconds() < self.CLEANUP_INTERVAL_SECONDS:
            return
        
        expired_ids = [
            captcha_id for captcha_id, data in self._captcha_store.items()
            if data["expires_at"] < now
        ]
        
        for captcha_id in expired_ids:
            del self._captcha_store[captcha_id]

        self._last_cleanup = now
    
    def generate_captcha(self, session_id: Optional[str] = None) -> Tuple[str, str, str]:
        self._cleanup_expired()
        
        captcha_code = self._generate_code()
        captcha_id = self._generate_id(session_id)
        
        captcha_image = self._generate_captcha_image(captcha_code)
        
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.CAPTCHA_EXPIRY_MINUTES)
        self._captcha_store[captcha_id] = {
            "code": captcha_code,
            "expires_at": expires_at,
            "attempts": 0,
            "created_at": datetime.now(timezone.utc),
        }
        
        return captcha_id, captcha_code, captcha_image
    
    def _generate_id(self, session_id: Optional[str] = None) -> str:
        if session_id:
            return f"{session_id}_{uuid.uuid4().hex[:8]}"
        return uuid.uuid4().hex
    
    def validate_captcha(self, captcha_id: str, user_input: str) -> Tuple[bool, str]:
        self._cleanup_expired()
        
        user_input = user_input.strip()

        if captcha_id not in self._captcha_store:
            return False, "Invalid or expired CAPTCHA. Please request a new one."

        captcha_data = self._captcha_store[captcha_id]

        if datetime.now(timezone.utc) > captcha_data["expires_at"]:
            del self._captcha_store[captcha_id]
            return False, "CAPTCHA expired. Please request a new one."

        captcha_data["attempts"] += 1

        if captcha_data.get("validated", False):
            validated_at = captcha_data.get("validated_at")
            if validated_at and (datetime.now(timezone.utc) - validated_at).total_seconds() < 300:
                return True, ""
            else:
                del self._captcha_store[captcha_id]
                return False, "CAPTCHA validation expired. Please request a new one."

        stored_code = captcha_data["code"]
        is_valid = stored_code == user_input

        if is_valid:
            captcha_data["validated"] = True
            captcha_data["validated_at"] = datetime.now(timezone.utc)
            captcha_data["expires_at"] = datetime.now(timezone.utc) + timedelta(minutes=5)
            return True, ""
        else:
            return False, "Invalid CAPTCHA code. Please try again."
    
    def get_captcha_info(self, captcha_id: str) -> Optional[Dict]:
        self._cleanup_expired()
        
        if captcha_id not in self._captcha_store:
            return None
        
        captcha_data = self._captcha_store[captcha_id]
        
        if datetime.now(timezone.utc) > captcha_data["expires_at"]:
            del self._captcha_store[captcha_id]
            return None
        
        return {
            "code": captcha_data["code"],
            "expires_at": captcha_data["expires_at"].isoformat(),
            "attempts": captcha_data["attempts"],
        }


captcha_service = CaptchaService()

