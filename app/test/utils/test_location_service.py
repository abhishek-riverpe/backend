import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from ...utils.location_service import get_location_from_ip, get_location_from_client


class TestGetLocationFromIp:
    """Tests for get_location_from_ip function"""
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_none(self):
        """Test with None IP address"""
        result = await get_location_from_ip(None)
        
        assert result["country"] is None
        assert result["city"] is None
        assert result["latitude"] is None
        assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_localhost(self):
        """Test with localhost IP"""
        result = await get_location_from_ip("127.0.0.1")
        
        assert result["country"] is None
        assert result["city"] is None
        assert result["latitude"] is None
        assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_private_network_192(self):
        """Test with private network IP (192.168.x.x)"""
        result = await get_location_from_ip("192.168.1.1")
        
        assert result["country"] is None
        assert result["city"] is None
        assert result["latitude"] is None
        assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_private_network_10(self):
        """Test with private network IP (10.x.x.x)"""
        result = await get_location_from_ip("10.0.0.1")
        
        assert result["country"] is None
        assert result["city"] is None
        assert result["latitude"] is None
        assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_localhost_v6(self):
        """Test with IPv6 localhost"""
        result = await get_location_from_ip("::1")
        
        assert result["country"] is None
        assert result["city"] is None
        assert result["latitude"] is None
        assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_success(self):
        """Test successful location retrieval"""
        mock_response_data = {
            "status": "success",
            "country": "United States",
            "city": "New York",
            "lat": 40.7128,
            "lon": -74.0060
        }
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_response_data
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_ip("8.8.8.8")
            
            assert result["country"] == "United States"
            assert result["city"] == "New York"
            assert result["latitude"] == 40.7128
            assert result["longitude"] == -74.0060
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_api_failure(self):
        """Test when API returns failure status"""
        mock_response_data = {
            "status": "fail",
            "message": "invalid query"
        }
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_response_data
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_ip("8.8.8.8")
            
            assert result["country"] is None
            assert result["city"] is None
            assert result["latitude"] is None
            assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_non_200_status(self):
        """Test when API returns non-200 status"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_ip("8.8.8.8")
            
            assert result["country"] is None
            assert result["city"] is None
            assert result["latitude"] is None
            assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_timeout(self):
        """Test when API call times out"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_ip("8.8.8.8")
            
            assert result["country"] is None
            assert result["city"] is None
            assert result["latitude"] is None
            assert result["longitude"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_ip_exception(self):
        """Test when API call raises exception"""
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=Exception("Network error"))
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_ip("8.8.8.8")
            
            assert result["country"] is None
            assert result["city"] is None
            assert result["latitude"] is None
            assert result["longitude"] is None


class TestGetLocationFromClient:
    """Tests for get_location_from_client function"""
    
    @pytest.mark.asyncio
    async def test_get_location_from_client_with_headers(self):
        """Test with location headers provided"""
        mock_request = MagicMock()
        mock_request.headers = {
            "X-User-Latitude": "40.7128",
            "X-User-Longitude": "-74.0060",
            "X-User-City": "New York",
            "X-User-Country": "United States"
        }
        
        result = await get_location_from_client(mock_request)
        
        assert result["latitude"] == 40.7128
        assert result["longitude"] == -74.0060
        assert result["city"] == "New York"
        assert result["country"] == "United States"
    
    @pytest.mark.asyncio
    async def test_get_location_from_client_with_lat_lon_only(self):
        """Test with only latitude and longitude headers"""
        mock_request = MagicMock()
        mock_request.headers = {
            "X-User-Latitude": "40.7128",
            "X-User-Longitude": "-74.0060"
        }
        mock_request.client.host = "127.0.0.1"
        
        result = await get_location_from_client(mock_request)
        
        assert result["latitude"] == 40.7128
        assert result["longitude"] == -74.0060
        assert result["city"] is None
        assert result["country"] is None
    
    @pytest.mark.asyncio
    async def test_get_location_from_client_invalid_lat_lon(self):
        """Test with invalid latitude/longitude values"""
        mock_request = MagicMock()
        mock_request.headers = {
            "X-User-Latitude": "invalid",
            "X-User-Longitude": "-74.0060"
        }
        mock_request.client.host = "8.8.8.8"
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "success",
                "country": "United States",
                "city": "New York",
                "lat": 40.7128,
                "lon": -74.0060
            }
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_client(mock_request)
            
            # Should fall back to IP lookup
            assert result["country"] == "United States"
    
    @pytest.mark.asyncio
    async def test_get_location_from_client_no_headers_falls_back_to_ip(self):
        """Test that function falls back to IP lookup when no headers"""
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client.host = "8.8.8.8"
        
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "success",
                "country": "United States",
                "city": "New York",
                "lat": 40.7128,
                "lon": -74.0060
            }
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__.return_value = mock_client
            
            result = await get_location_from_client(mock_request)
            
            assert result["country"] == "United States"
            assert result["city"] == "New York"
    
    @pytest.mark.asyncio
    async def test_get_location_from_client_no_client_host(self):
        """Test when request has no client host"""
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client = None
        
        result = await get_location_from_client(mock_request)
        
        assert result["country"] is None
        assert result["city"] is None

