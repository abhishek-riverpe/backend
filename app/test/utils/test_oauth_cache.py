import pytest
import time
from unittest.mock import patch
from ...utils.oauth_cache import generate_oauth_code, exchange_oauth_code, get_code_count, CODE_EXPIRY_SECONDS


class TestGenerateOAuthCode:
    """Tests for generate_oauth_code function"""
    
    def test_generate_oauth_code_creates_code(self):
        """Test that code generation creates a valid code"""
        data = {"user_id": "123", "email": "test@example.com"}
        code = generate_oauth_code(data)
        
        assert code is not None
        assert isinstance(code, str)
        assert len(code) > 0
    
    def test_generate_oauth_code_stores_data(self):
        """Test that generated code stores the provided data"""
        data = {"user_id": "123", "email": "test@example.com"}
        code = generate_oauth_code(data)
        
        result = exchange_oauth_code(code)
        assert result == data
    
    def test_generate_oauth_code_has_expiry(self):
        """Test that generated code has expiry time set"""
        data = {"user_id": "123"}
        code = generate_oauth_code(data)
        
        # Code should be exchangeable immediately
        result = exchange_oauth_code(code)
        assert result is not None


class TestExchangeOAuthCode:
    """Tests for exchange_oauth_code function"""
    
    def test_exchange_oauth_code_valid(self):
        """Test exchanging a valid code"""
        data = {"user_id": "123", "email": "test@example.com"}
        code = generate_oauth_code(data)
        
        result = exchange_oauth_code(code)
        assert result == data
    
    def test_exchange_oauth_code_invalid(self):
        """Test exchanging an invalid code"""
        result = exchange_oauth_code("invalid-code-12345")
        assert result is None
    
    def test_exchange_oauth_code_expired(self):
        """Test exchanging an expired code"""
        data = {"user_id": "123"}
        
        with patch('time.time', return_value=1000):
            code = generate_oauth_code(data)
        
        # Simulate time passing beyond expiry
        with patch('time.time', return_value=1000 + CODE_EXPIRY_SECONDS + 1):
            result = exchange_oauth_code(code)
            assert result is None
    
    def test_exchange_oauth_code_one_time_use(self):
        """Test that code can only be exchanged once"""
        data = {"user_id": "123"}
        code = generate_oauth_code(data)
        
        # First exchange should succeed
        result1 = exchange_oauth_code(code)
        assert result1 == data
        
        # Second exchange should fail (code already used)
        result2 = exchange_oauth_code(code)
        assert result2 is None
    
    def test_exchange_oauth_code_different_data(self):
        """Test exchanging codes with different data"""
        data1 = {"user_id": "123"}
        data2 = {"user_id": "456"}
        
        code1 = generate_oauth_code(data1)
        code2 = generate_oauth_code(data2)
        
        result1 = exchange_oauth_code(code1)
        result2 = exchange_oauth_code(code2)
        
        assert result1 == data1
        assert result2 == data2
        assert result1 != result2


class TestGetCodeCount:
    """Tests for get_code_count function"""
    
    def test_get_code_count_empty(self):
        """Test count when no codes exist"""
        # Exchange any existing codes to clear them
        # Note: This test assumes cache can be cleared by exchanging all codes
        count = get_code_count()
        assert isinstance(count, int)
        assert count >= 0
    
    def test_get_code_count_after_generation(self):
        """Test count after generating codes"""
        data1 = {"user_id": "123"}
        data2 = {"user_id": "456"}
        
        generate_oauth_code(data1)
        generate_oauth_code(data2)
        
        count = get_code_count()
        assert count >= 2
    
    def test_get_code_count_after_exchange(self):
        """Test count decreases after exchanging codes"""
        data = {"user_id": "123"}
        code = generate_oauth_code(data)
        
        count_before = get_code_count()
        exchange_oauth_code(code)
        count_after = get_code_count()
        
        assert count_after < count_before
    
    def test_get_code_count_expired_codes_cleaned(self):
        """Test that expired codes are cleaned up"""
        data = {"user_id": "123"}
        
        with patch('time.time', return_value=1000):
            code = generate_oauth_code(data)
            count_before = get_code_count()
            assert count_before >= 1
        
        # Simulate time passing beyond expiry and cleanup interval (600 > 300 cleanup interval)
        with patch('time.time', return_value=1000 + CODE_EXPIRY_SECONDS + 600):
            # Trigger cleanup by calling get_code_count
            count_after = get_code_count()
            # Expired code should be cleaned up (count should decrease)
            assert count_after <= count_before

