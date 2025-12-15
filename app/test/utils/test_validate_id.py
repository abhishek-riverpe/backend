import pytest
from ...utils.validate_id import validate_user_id


class TestValidateUserId:
    """Tests for validate_user_id function"""
    
    def test_validate_user_id_valid_uppercase(self):
        """Test validation with valid uppercase UUID"""
        valid_id = "550E8400-E29B-41D4-A716-446655440000"
        assert validate_user_id(valid_id) is True
    
    def test_validate_user_id_valid_lowercase(self):
        """Test validation with valid lowercase UUID"""
        valid_id = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_user_id(valid_id) is True
    
    def test_validate_user_id_valid_mixed_case(self):
        """Test validation with valid mixed case UUID"""
        valid_id = "550E8400-e29B-41D4-A716-446655440000"
        assert validate_user_id(valid_id) is True
    
    def test_validate_user_id_invalid_missing_segments(self):
        """Test validation with missing segments"""
        invalid_id = "550E8400-E29B-41D4-A716"
        assert validate_user_id(invalid_id) is False
    
    def test_validate_user_id_invalid_wrong_format(self):
        """Test validation with wrong format"""
        invalid_id = "550E8400E29B41D4A716446655440000"
        assert validate_user_id(invalid_id) is False
    
    def test_validate_user_id_invalid_invalid_characters(self):
        """Test validation with invalid characters"""
        invalid_id = "550E8400-E29B-41D4-A716-44665544000G"
        assert validate_user_id(invalid_id) is False
    
    def test_validate_user_id_invalid_too_short(self):
        """Test validation with too short ID"""
        invalid_id = "550E8400-E29B-41D4-A716"
        assert validate_user_id(invalid_id) is False
    
    def test_validate_user_id_invalid_empty_string(self):
        """Test validation with empty string"""
        assert validate_user_id("") is False
    
    def test_validate_user_id_invalid_not_uuid_format(self):
        """Test validation with non-UUID format"""
        invalid_id = "user-123-456"
        assert validate_user_id(invalid_id) is False
    
    def test_validate_user_id_valid_different_variants(self):
        """Test validation with different valid UUID variants"""
        valid_ids = [
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "12345678-1234-5678-9012-123456789012",
        ]
        for valid_id in valid_ids:
            assert validate_user_id(valid_id) is True, f"Should validate: {valid_id}"

