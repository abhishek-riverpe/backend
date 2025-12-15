import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from prisma.errors import UniqueViolationError
from ...services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID
from ...utils.enums import AccountStatusEnum


class TestSaveFundingAccountToDb:
    """Tests for save_funding_account_to_db function"""
    
    @pytest.mark.asyncio
    async def test_save_funding_account_success(self):
        """Test successful funding account save"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "jurisdictionId": "jurisdiction-123",
            "providerId": "provider-123",
            "status": "active",
            "accountInfo": {
                "bank_name": "Test Bank",
                "bank_address": "123 Main St",
                "bank_routing_number": "123456789",
                "bank_account_number": "987654321",
                "bank_beneficiary_name": "John Doe",
                "bank_beneficiary_address": "456 Oak Ave",
                "payment_rail": "ACH",
                "currency": "USD"
            }
        }
        
        mock_account = MagicMock()
        mock_account.id = "account-123"
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(return_value=mock_account)
            
            result = await save_funding_account_to_db("entity-123", zynk_response_data)
            
            assert result == mock_account
            mock_prisma.funding_accounts.create.assert_called_once()
            create_call = mock_prisma.funding_accounts.create.call_args
            data = create_call[1]["data"]
            assert data["entity_id"] == "entity-123"
            assert data["zynk_funding_account_id"] == "zynk-funding-123"
            assert data["status"] == AccountStatusEnum.ACTIVE
            assert data["currency"] == "USD"
    
    @pytest.mark.asyncio
    async def test_save_funding_account_inactive_status(self):
        """Test saving account with inactive status"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "status": "inactive",
            "accountInfo": {
                "currency": "USD"
            }
        }
        
        mock_account = MagicMock()
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(return_value=mock_account)
            
            await save_funding_account_to_db("entity-123", zynk_response_data)
            
            create_call = mock_prisma.funding_accounts.create.call_args
            data = create_call[1]["data"]
            assert data["status"] == AccountStatusEnum.INACTIVE
    
    @pytest.mark.asyncio
    async def test_save_funding_account_currency_uppercase(self):
        """Test that currency is converted to uppercase"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "accountInfo": {
                "currency": "usd"  # lowercase
            }
        }
        
        mock_account = MagicMock()
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(return_value=mock_account)
            
            await save_funding_account_to_db("entity-123", zynk_response_data)
            
            create_call = mock_prisma.funding_accounts.create.call_args
            data = create_call[1]["data"]
            assert data["currency"] == "USD"
    
    @pytest.mark.asyncio
    async def test_save_funding_account_default_jurisdiction(self):
        """Test that default jurisdiction is used when not provided"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "accountInfo": {
                "currency": "USD"
            }
        }
        
        mock_account = MagicMock()
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(return_value=mock_account)
            
            await save_funding_account_to_db("entity-123", zynk_response_data)
            
            create_call = mock_prisma.funding_accounts.create.call_args
            data = create_call[1]["data"]
            assert data["jurisdiction_id"] == US_FUNDING_JURISDICTION_ID
    
    @pytest.mark.asyncio
    async def test_save_funding_account_handles_unique_violation(self):
        """Test handling of unique violation (account already exists)"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "accountInfo": {
                "currency": "USD"
            }
        }
        
        existing_account = MagicMock()
        existing_account.id = "existing-account-123"
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            # Mock the create to raise UniqueViolationError with proper data structure
            unique_error = UniqueViolationError(data={"code": "P2002", "meta": {"target": ["entity_id"]}})
            mock_prisma.funding_accounts.create = AsyncMock(side_effect=unique_error)
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=existing_account)
            
            result = await save_funding_account_to_db("entity-123", zynk_response_data)
            
            # Should return existing account when unique violation occurs
            assert result == existing_account
            mock_prisma.funding_accounts.find_first.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_funding_account_handles_missing_fields(self):
        """Test saving account with missing optional fields"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "accountInfo": {}
        }
        
        mock_account = MagicMock()
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(return_value=mock_account)
            
            result = await save_funding_account_to_db("entity-123", zynk_response_data)
            
            assert result == mock_account
            create_call = mock_prisma.funding_accounts.create.call_args
            data = create_call[1]["data"]
            # Should have defaults for missing fields
            assert data["currency"] == "USD"  # Default
            assert data["bank_name"] == ""  # Empty string default
    
    @pytest.mark.asyncio
    async def test_save_funding_account_raises_other_exceptions(self):
        """Test that non-unique violations raise exceptions"""
        zynk_response_data = {
            "id": "zynk-funding-123",
            "accountInfo": {"currency": "USD"}
        }
        
        with patch('app.services.funding_account_service.prisma') as mock_prisma:
            mock_prisma.funding_accounts.create = AsyncMock(side_effect=Exception("Database error"))
            
            with pytest.raises(Exception, match="Database error"):
                await save_funding_account_to_db("entity-123", zynk_response_data)

