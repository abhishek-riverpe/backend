import pytest
from fastapi import status
from ...utils.errors import upstream_error, internal_error


class TestUpstreamError:
    """Tests for upstream_error function"""
    
    def test_upstream_error_default(self):
        """Test upstream_error with default parameters"""
        error = upstream_error()
        
        assert isinstance(error, Exception)
        assert error.status_code == status.HTTP_502_BAD_GATEWAY
        assert "Upstream service is currently unavailable" in error.detail
    
    def test_upstream_error_custom_message(self):
        """Test upstream_error with custom message"""
        custom_message = "Custom upstream error message"
        error = upstream_error(user_message=custom_message)
        
        assert error.status_code == status.HTTP_502_BAD_GATEWAY
        assert error.detail == custom_message
    
    def test_upstream_error_custom_status_code(self):
        """Test upstream_error with custom status code"""
        error = upstream_error(status_code=status.HTTP_504_GATEWAY_TIMEOUT)
        
        assert error.status_code == status.HTTP_504_GATEWAY_TIMEOUT
        assert "Upstream service is currently unavailable" in error.detail
    
    def test_upstream_error_custom_all(self):
        """Test upstream_error with custom message and status code"""
        custom_message = "Service timeout"
        error = upstream_error(user_message=custom_message, status_code=status.HTTP_504_GATEWAY_TIMEOUT)
        
        assert error.status_code == status.HTTP_504_GATEWAY_TIMEOUT
        assert error.detail == custom_message


class TestInternalError:
    """Tests for internal_error function"""
    
    def test_internal_error_default(self):
        """Test internal_error with default parameters"""
        error = internal_error()
        
        assert isinstance(error, Exception)
        assert error.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Internal server error" in error.detail
    
    def test_internal_error_custom_message(self):
        """Test internal_error with custom message"""
        custom_message = "Custom internal error message"
        error = internal_error(user_message=custom_message)
        
        assert error.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert error.detail == custom_message
    
    def test_internal_error_custom_status_code(self):
        """Test internal_error with custom status code"""
        error = internal_error(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        assert error.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "Internal server error" in error.detail
    
    def test_internal_error_custom_all(self):
        """Test internal_error with custom message and status code"""
        custom_message = "Service maintenance"
        error = internal_error(user_message=custom_message, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        assert error.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert error.detail == custom_message

