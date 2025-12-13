import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from fastapi import HTTPException
from ...services.zynk_client import _auth_header, get_kyc_link_from_zynk, create_funding_account_from_zynk
from ...utils.errors import upstream_error


class TestAuthHeader:
    """Tests for _auth_header function"""
    
    def test_auth_header_success(self):
        """Test successful auth header creation"""
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-api-key"
            
            result = _auth_header()
            
            assert result == {"x-api-token": "test-api-key"}
    
    def test_auth_header_no_api_key(self):
        """Test auth header when API key is not configured"""
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = None
            
            with pytest.raises(HTTPException) as exc_info:
                _auth_header()
            
            assert exc_info.value.status_code == 500
            assert "API key not configured" in exc_info.value.detail


class TestGetKycLinkFromZynk:
    """Tests for get_kyc_link_from_zynk function"""
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_success(self):
        """Test successful KYC link retrieval"""
        mock_response_data = {
            "success": True,
            "data": {
                "kycLink": "https://kyc.example.com/verify/123"
            }
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                result = await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert result["kycLink"] == "https://kyc.example.com/verify/123"
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_kyc_already_completed(self):
        """Test when KYC is already completed"""
        mock_response_data = {
            "error": {
                "details": "kyc for this entity has already been done"
            },
            "message": "KYC already completed"
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                result = await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert result["kycCompleted"] is True
                assert "already been completed" in result["message"]
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_non_200_status(self):
        """Test handling of non-200 status code"""
        mock_response_data = {
            "error": {"message": "Internal server error"},
            "message": "Internal server error"
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_no_success_flag(self):
        """Test when response doesn't have success flag"""
        mock_response_data = {
            "data": {
                "kycLink": "https://kyc.example.com/verify/123"
            }
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_no_kyc_link_in_response(self):
        """Test when response doesn't contain kycLink"""
        mock_response_data = {
            "success": True,
            "data": {}
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_request_error_retry(self):
        """Test retry logic on request error"""
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                # First call fails, second succeeds
                mock_response_data = {
                    "success": True,
                    "data": {
                        "kycLink": "https://kyc.example.com/verify/123"
                    }
                }
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_response_data
                
                mock_client.post = AsyncMock(side_effect=[
                    httpx.RequestError("Network error"),
                    mock_response
                ])
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                result = await get_kyc_link_from_zynk("zynk-entity-123", "routing-123")
                
                assert result["kycLink"] == "https://kyc.example.com/verify/123"
                assert mock_client.post.call_count == 2


class TestCreateFundingAccountFromZynk:
    """Tests for create_funding_account_from_zynk function"""
    
    @pytest.mark.asyncio
    async def test_create_funding_account_success(self):
        """Test successful funding account creation"""
        mock_response_data = {
            "success": True,
            "data": {
                "data": {
                    "id": "zynk-funding-123",
                    "jurisdictionId": "jurisdiction-123"
                }
            }
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                result = await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert result["id"] == "zynk-funding-123"
                assert result["jurisdictionId"] == "jurisdiction-123"
    
    @pytest.mark.asyncio
    async def test_create_funding_account_non_200_status(self):
        """Test handling of non-200 status code"""
        mock_response_data = {"error": "Bad request"}
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_create_funding_account_no_success_flag(self):
        """Test when response doesn't have success flag"""
        mock_response_data = {
            "data": {
                "data": {
                    "id": "zynk-funding-123"
                }
            }
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_create_funding_account_no_id(self):
        """Test when response doesn't contain id"""
        mock_response_data = {
            "success": True,
            "data": {
                "data": {}
            }
        }
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_create_funding_account_invalid_json(self):
        """Test handling of invalid JSON response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                with pytest.raises(HTTPException) as exc_info:
                    await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert exc_info.value.status_code == 502
    
    @pytest.mark.asyncio
    async def test_create_funding_account_request_error_retry(self):
        """Test retry logic on request error"""
        with patch('app.services.zynk_client.settings') as mock_settings:
            mock_settings.zynk_api_key = "test-key"
            mock_settings.zynk_base_url = "https://api.zynk.com"
            mock_settings.zynk_timeout_s = 30
            
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                # First call fails, second succeeds
                mock_response_data = {
                    "success": True,
                    "data": {
                        "data": {
                            "id": "zynk-funding-123"
                        }
                    }
                }
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_response_data
                
                mock_client.post = AsyncMock(side_effect=[
                    httpx.RequestError("Network error"),
                    mock_response
                ])
                mock_client_class.return_value.__aenter__.return_value = mock_client
                
                result = await create_funding_account_from_zynk("zynk-entity-123", "jurisdiction-123")
                
                assert result["id"] == "zynk-funding-123"
                assert mock_client.post.call_count == 2

