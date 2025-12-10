"""
Tests for log_sanitizer utility

Run with: pytest app/utils/test_log_sanitizer.py -v
"""

import pytest
from app.utils.log_sanitizer import (
    sanitize_for_log,
    sanitize_pii,
    sanitize_dict_for_log,
)


class TestSanitizeForLog:
    """Test cases for sanitize_for_log function"""

    def test_safe_email(self):
        """Test that safe emails pass through unchanged"""
        email = "user@example.com"
        result = sanitize_for_log(email)
        assert result == email

    def test_crlf_injection(self):
        """Test that CRLF injection attempts are sanitized"""
        malicious = "user@example.com\nADMIN=true"
        result = sanitize_for_log(malicious)
        # Should be base64 encoded since it contains newline
        assert result.startswith("[BASE64]")
        assert "\n" not in result

    def test_carriage_return_injection(self):
        """Test that CR injection is sanitized"""
        malicious = "user@test.com\rINJECTION"
        result = sanitize_for_log(malicious)
        assert result.startswith("[BASE64]")
        assert "\r" not in result

    def test_replace_encoding(self):
        """Test replace encoding mode"""
        malicious = "user\n@test.com"
        result = sanitize_for_log(malicious, encoding='replace')
        assert "\n" not in result
        assert "_" in result

    def test_remove_encoding(self):
        """Test remove encoding mode"""
        malicious = "user\n@test.com"
        result = sanitize_for_log(malicious, encoding='remove')
        assert "\n" not in result
        assert result == "user@test.com"

    def test_null_value(self):
        """Test handling of None values"""
        result = sanitize_for_log(None)
        assert result == "[NULL]"

    def test_max_length_truncation(self):
        """Test that long values are truncated"""
        long_string = "a" * 500
        result = sanitize_for_log(long_string, max_length=100)
        assert len(result) <= 100

    def test_special_chars_safe(self):
        """Test that safe special chars are allowed"""
        safe = "user-name_123@example.com"
        result = sanitize_for_log(safe)
        assert result == safe

    def test_sql_injection_attempt(self):
        """Test that SQL injection-like strings are sanitized"""
        malicious = "user'; DROP TABLE users--"
        result = sanitize_for_log(malicious)
        # Contains unsafe chars (;--) so should be base64 encoded
        assert result.startswith("[BASE64]")

    def test_xss_attempt(self):
        """Test that XSS-like strings are sanitized"""
        malicious = "<script>alert('xss')</script>"
        result = sanitize_for_log(malicious)
        # Contains unsafe chars (<>) so should be base64 encoded
        assert result.startswith("[BASE64]")

    def test_log_forging_attempt(self):
        """Test classic log forging attack"""
        # Attacker tries to inject fake log entry
        malicious = "innocent\n[ERROR] Fake admin access granted"
        result = sanitize_for_log(malicious)
        assert result.startswith("[BASE64]")
        # Verify no newline in output
        assert "\n" not in result

    def test_unicode_handling(self):
        """Test that unicode characters are handled"""
        unicode_str = "user@example.com\u0000"
        result = sanitize_for_log(unicode_str)
        # Should be base64 encoded due to null byte
        assert result.startswith("[BASE64]")

    def test_integer_conversion(self):
        """Test that integers are converted to string"""
        result = sanitize_for_log(12345)
        assert result == "12345"

    def test_boolean_conversion(self):
        """Test that booleans are converted to string"""
        result = sanitize_for_log(True)
        assert result == "True"


class TestSanitizePII:
    """Test cases for sanitize_pii function"""

    def test_email_masking(self):
        """Test that emails are masked correctly"""
        email = "user@example.com"
        result = sanitize_pii(email)
        assert result == "use***"

    def test_custom_prefix_length(self):
        """Test custom prefix length"""
        email = "user@example.com"
        result = sanitize_pii(email, show_prefix=5)
        assert result == "user@***"

    def test_short_value(self):
        """Test masking of very short values"""
        result = sanitize_pii("ab")
        assert result == "***"

    def test_null_value(self):
        """Test handling of None"""
        result = sanitize_pii(None)
        assert result == "[NULL]"

    def test_pii_with_injection(self):
        """Test PII masking also sanitizes injection attempts"""
        malicious = "user\n@evil.com"
        result = sanitize_pii(malicious)
        # Should still be masked and no newlines
        assert "\n" not in result
        assert "***" in result


class TestSanitizeDictForLog:
    """Test cases for sanitize_dict_for_log function"""

    def test_simple_dict(self):
        """Test sanitization of simple dictionary"""
        data = {"email": "user@test.com", "name": "John"}
        result = sanitize_dict_for_log(data)
        assert result["email"] == "user@test.com"
        assert result["name"] == "John"

    def test_sensitive_keys_redacted(self):
        """Test that sensitive keys are redacted"""
        data = {
            "email": "user@test.com",
            "password": "secret123",
            "api_key": "key123",
            "token": "abc123"
        }
        result = sanitize_dict_for_log(data)
        assert result["password"] == "[REDACTED]"
        assert result["api_key"] == "[REDACTED]"
        assert result["token"] == "[REDACTED]"
        assert result["email"] == "user@test.com"

    def test_nested_dict(self):
        """Test sanitization of nested dictionaries"""
        data = {
            "user": {
                "email": "test@test.com",
                "password": "secret"
            }
        }
        result = sanitize_dict_for_log(data)
        assert result["user"]["password"] == "[REDACTED]"
        assert result["user"]["email"] == "test@test.com"

    def test_list_values(self):
        """Test sanitization of list values"""
        data = {
            "emails": ["user1@test.com", "user2\n@evil.com"]
        }
        result = sanitize_dict_for_log(data)
        assert result["emails"][0] == "user1@test.com"
        # Second email should be base64 encoded due to newline
        assert result["emails"][1].startswith("[BASE64]")

    def test_case_insensitive_sensitive_keys(self):
        """Test that sensitive key matching is case-insensitive"""
        data = {
            "PASSWORD": "secret",
            "Authorization": "Bearer token",
            "API_KEY": "key123"
        }
        result = sanitize_dict_for_log(data)
        assert result["PASSWORD"] == "[REDACTED]"
        assert result["Authorization"] == "[REDACTED]"
        assert result["API_KEY"] == "[REDACTED]"

    def test_custom_sensitive_keys(self):
        """Test custom sensitive keys"""
        data = {
            "ssn": "123-45-6789",
            "email": "user@test.com"
        }
        result = sanitize_dict_for_log(data, sensitive_keys={'ssn'})
        assert result["ssn"] == "[REDACTED]"
        assert result["email"] == "user@test.com"


class TestLogInjectionScenarios:
    """Test real-world log injection scenarios"""

    def test_forged_admin_entry(self):
        """Test prevention of forged admin log entry"""
        # Attacker tries to create fake admin access log
        attack = "normaluser\n[INFO] Admin access granted for root"
        result = sanitize_for_log(attack)
        assert "\n" not in result
        assert "[INFO]" not in result

    def test_session_hijacking_attempt(self):
        """Test prevention of session token injection"""
        attack = "user@test.com\nSESSION_TOKEN=admin_token_12345"
        result = sanitize_for_log(attack)
        assert "\n" not in result
        assert result.startswith("[BASE64]")

    def test_multi_line_injection(self):
        """Test prevention of multi-line log injection"""
        attack = "user\r\n[ERROR] System compromised\r\n[INFO] Backdoor installed"
        result = sanitize_for_log(attack)
        assert "\r" not in result
        assert "\n" not in result

    def test_null_byte_injection(self):
        """Test prevention of null byte injection"""
        attack = "user@test.com\x00ADMIN"
        result = sanitize_for_log(attack)
        # Should be base64 encoded
        assert result.startswith("[BASE64]")

    def test_combined_attack(self):
        """Test combined injection techniques"""
        attack = "user'; DROP TABLE users;--\r\n[ADMIN] Access granted"
        result = sanitize_for_log(attack)
        assert "\r" not in result
        assert "\n" not in result
        assert "DROP TABLE" not in result


class TestPerformance:
    """Test performance characteristics"""

    def test_large_input_handling(self):
        """Test that very large inputs are handled efficiently"""
        large_input = "a" * 10000
        result = sanitize_for_log(large_input, max_length=200)
        # Should be truncated
        assert len(result) <= 200

    def test_repeated_sanitization(self):
        """Test that repeated sanitization is idempotent for safe values"""
        safe_value = "user@example.com"
        result1 = sanitize_for_log(safe_value)
        result2 = sanitize_for_log(result1)
        assert result1 == result2 == safe_value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
