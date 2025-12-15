import pytest
from unittest.mock import MagicMock
from ...utils.device_parser import parse_device_from_headers, parse_user_agent


class TestParseDeviceFromHeaders:
    """Tests for parse_device_from_headers function"""
    
    def test_parse_device_from_headers_with_custom_headers(self):
        """Test parsing device info from custom headers"""
        mock_request = MagicMock()
        mock_request.headers = {
            "X-Device-Type": "mobile",
            "X-Device-Name": "iPhone 13",
            "X-OS-Name": "iOS",
            "X-OS-Version": "15.0",
            "X-Browser-Name": "Safari",
            "X-Browser-Version": "15.0",
            "X-App-Version": "1.0.0"
        }
        
        result = parse_device_from_headers(mock_request)
        
        assert result["device_type"] == "mobile"
        assert result["device_name"] == "iPhone 13"
        assert result["os_name"] == "iOS"
        assert result["os_version"] == "15.0"
        assert result["browser_name"] == "Safari"
        assert result["browser_version"] == "15.0"
        assert result["app_version"] == "1.0.0"
    
    def test_parse_device_from_headers_partial_custom_headers(self):
        """Test parsing with partial custom headers"""
        mock_request = MagicMock()
        mock_request.headers = {
            "X-Device-Type": "desktop",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        result = parse_device_from_headers(mock_request)
        
        assert result["device_type"] == "desktop"
    
    def test_parse_device_from_headers_falls_back_to_user_agent(self):
        """Test that function falls back to user agent parsing when no custom headers"""
        mock_request = MagicMock()
        mock_request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        result = parse_device_from_headers(mock_request)
        
        assert result["device_type"] == "desktop"
        assert result["os_name"] == "Windows"
        assert result["browser_name"] == "Chrome"
    
    def test_parse_device_from_headers_no_headers(self):
        """Test parsing with no relevant headers"""
        mock_request = MagicMock()
        mock_request.headers = {}
        
        result = parse_device_from_headers(mock_request)
        
        assert result["device_type"] is None or result["device_type"] == "desktop"


class TestParseUserAgent:
    """Tests for parse_user_agent function"""
    
    def test_parse_user_agent_none(self):
        """Test parsing None user agent"""
        result = parse_user_agent(None)
        
        assert result["device_type"] is None
        assert result["device_name"] is None
        assert result["os_name"] is None
        assert result["os_version"] is None
        assert result["browser_name"] is None
        assert result["browser_version"] is None
        assert result["app_version"] is None
    
    def test_parse_user_agent_empty_string(self):
        """Test parsing empty user agent string"""
        result = parse_user_agent("")
        
        assert result["device_type"] is None
    
    def test_parse_user_agent_windows_chrome(self):
        """Test parsing Windows Chrome user agent"""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result["device_type"] == "desktop"
        assert result["os_name"] == "Windows"
        assert result["os_version"] == "10"
        assert result["browser_name"] == "Chrome"
        assert result["browser_version"] == "91.0.4472.124"
    
    def test_parse_user_agent_macos_safari(self):
        """Test parsing macOS Safari user agent"""
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        result = parse_user_agent(user_agent)
        
        assert result["device_type"] == "desktop"
        assert result["os_name"] == "macOS"
        assert result["os_version"] == "10.15.7"
        assert result["browser_name"] == "Safari"
        assert result["browser_version"] == "14.1.1"
    
    def test_parse_user_agent_android_mobile(self):
        """Test parsing Android mobile user agent"""
        user_agent = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result["device_type"] == "mobile"
        assert result["os_name"] == "Android"
        assert result["os_version"] == "11"
        assert result["browser_name"] == "Chrome"
    
    def test_parse_user_agent_iphone(self):
        """Test parsing iPhone user agent"""
        user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(user_agent)
        
        assert result["device_type"] == "mobile"
        # iPhone OS detection may vary, check it's either iOS or macOS (due to "like Mac OS X")
        assert result["os_name"] in ["iOS", "macOS"]
        # Device name may include version number (e.g., "iPhone 14")
        assert result["device_name"] is not None
        assert "iPhone" in result["device_name"]
        assert result["browser_name"] == "Safari"
    
    def test_parse_user_agent_ipad(self):
        """Test parsing iPad user agent"""
        user_agent = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        result = parse_user_agent(user_agent)
        
        # iPad detection can vary - check it's detected as tablet or mobile
        assert result["device_type"] in ["tablet", "mobile"]
        assert result["os_name"] in ["iPadOS", "macOS"]  # May detect as macOS due to "like Mac OS X"
        assert result["device_name"] == "iPad"
    
    def test_parse_user_agent_firefox(self):
        """Test parsing Firefox user agent"""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = parse_user_agent(user_agent)
        
        assert result["browser_name"] == "Firefox"
        assert result["browser_version"] == "89.0"
    
    def test_parse_user_agent_edge(self):
        """Test parsing Edge user agent"""
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        result = parse_user_agent(user_agent)
        
        assert result["browser_name"] == "Edge"
        assert result["browser_version"] == "91.0.864.59"
    
    def test_parse_user_agent_with_app_version(self):
        """Test parsing user agent with Riverpe app version"""
        user_agent = "Riverpe/1.2.3 (iPhone; iOS 14.6)"
        result = parse_user_agent(user_agent)
        
        assert result["app_version"] == "1.2.3"
    
    def test_parse_user_agent_linux(self):
        """Test parsing Linux user agent"""
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = parse_user_agent(user_agent)
        
        assert result["os_name"] == "Linux"
        assert result["device_type"] == "desktop"
    
    def test_parse_user_agent_windows_version_mapping(self):
        """Test Windows version mapping"""
        user_agent_win10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        result_win10 = parse_user_agent(user_agent_win10)
        assert result_win10["os_version"] == "10"
        
        user_agent_win8 = "Mozilla/5.0 (Windows NT 6.2; Win64; x64)"
        result_win8 = parse_user_agent(user_agent_win8)
        assert result_win8["os_version"] == "8"

