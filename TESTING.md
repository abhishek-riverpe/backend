# Testing Guide

This document provides all the test commands for running tests in the Riverpe server application.

## Prerequisites

- Python 3.14+ installed
- Dependencies installed (`pip install -r requirements.txt`)
- Virtual environment activated (if using one)

## Quick Start

### Run All Tests
```bash
python -m pytest --import-mode=importlib --tb=short
```

### Run All Tests with Verbose Output
```bash
python -m pytest --import-mode=importlib --tb=short -v
```

### Run All Tests with Detailed Traceback
```bash
python -m pytest --import-mode=importlib --tb=long -v
```

## Route Test Files

The following test files are located in `app/test/routes/`:

- `test_auth_routes.py` - Authentication routes (signup, signin, password reset, etc.)
- `test_captcha_routes.py` - CAPTCHA generation and validation
- `test_funding_account_routes.py` - Funding account management
- `test_kyc_routes.py` - KYC (Know Your Customer) status and links
- `test_otp_routes.py` - OTP (One-Time Password) sending and verification
- `test_teleport_routes.py` - Teleport operations
- `test_webhooks.py` - Webhook endpoints

## Running Tests by Route

### Authentication Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py
```

### CAPTCHA Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_captcha_routes.py
```

### Funding Account Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_funding_account_routes.py
```

### KYC Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_kyc_routes.py
```

### OTP Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_otp_routes.py
```

### Teleport Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_teleport_routes.py
```

### Webhook Routes
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_webhooks.py
```

## Running Specific Test Classes

### Authentication - Signup Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestSignup
```

### Authentication - Signin Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestSignin
```

### Authentication - Password Reset Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestForgotPassword
```

### Authentication - Change Password Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestChangePassword
```

### Funding Account - Get Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_funding_account_routes.py::TestGetFundingAccount
```

### Funding Account - Create Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_funding_account_routes.py::TestCreateFundingAccount
```

### KYC - Status Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_kyc_routes.py::TestGetKycStatus
```

### KYC - Link Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_kyc_routes.py::TestGetKycLink
```

### OTP - Send Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_otp_routes.py::TestSendOtp
```

### OTP - Email OTP Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_otp_routes.py::TestSendEmailOtp
```

### Webhook - Zynk Webhook Tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_webhooks.py::TestZynkWebhook
```

## Running Individual Tests

### Example: Run a specific test
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestSignup::test_signup_success
```

### Example: Run multiple specific tests
```bash
python -m pytest --import-mode=importlib --tb=short -v app/test/routes/test_auth_routes.py::TestSignup::test_signup_success app/test/routes/test_auth_routes.py::TestSignup::test_signup_email_already_exists
```

## Useful Test Options

### Stop on First Failure
```bash
python -m pytest --import-mode=importlib --tb=short -x
```

### Show Only Failed Tests Summary
```bash
python -m pytest --import-mode=importlib --tb=line --maxfail=5
```

### Run Tests with Coverage (if pytest-cov is installed)
```bash
python -m pytest --import-mode=importlib --tb=short --cov=app --cov-report=html
```

### Run Tests in Parallel (if pytest-xdist is installed)
```bash
python -m pytest --import-mode=importlib --tb=short -n auto
```

### Show Local Variables on Failure
```bash
python -m pytest --import-mode=importlib --tb=short -l
```

### Collect Tests Without Running (List All Tests)
```bash
python -m pytest --import-mode=importlib --co -q
```

## Traceback Options

- `--tb=short` - Shorter traceback format (default recommendation)
- `--tb=long` - Detailed traceback format
- `--tb=line` - One line per failure
- `--tb=no` - No traceback output
- `--tb=auto` - Default pytest traceback format

## Test Output Options

- `-v` or `--verbose` - Verbose output (shows each test name)
- `-q` or `--quiet` - Quiet output (minimal output)
- `-s` - Don't capture output (print statements visible)
- `-vv` - Very verbose (shows more details)

## Important Notes

1. **Always use `--import-mode=importlib`** - This is required for the tests to work correctly with the package structure.

2. **Configuration** - Test configuration is in `pytest.ini`:
   - Test paths: `app/test`
   - Python files: `test_*.py`
   - Async mode: `auto`
   - Python path: `.`

3. **Test Count** - Currently there are **76 tests** covering all route endpoints.

4. **Test Structure** - Tests are organized by route file:
   - Each route file has corresponding test file
   - Test classes group related test methods
   - Fixtures are defined for common mock objects

## Example Test Run Output

```bash
$ python -m pytest --import-mode=importlib --tb=short -v

============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-9.0.2, pluggy-1.6.0
collected 76 items

app/test/routes/test_auth_routes.py::TestSignup::test_signup_success PASSED [  1%]
app/test/routes/test_auth_routes.py::TestSignup::test_signup_email_already_exists PASSED [  2%]
...
app/test/routes/test_webhooks.py::TestZynkWebhook::test_receive_webhook_kyc_approved_creates_funding_account PASSED [100%]

======================= 76 passed, 40 warnings in 4.62s =======================
```

## Troubleshooting

### Import Errors
If you encounter import errors, ensure you're using `--import-mode=importlib`:
```bash
python -m pytest --import-mode=importlib --tb=short -v
```

### Test Not Found
Ensure you're running from the project root directory where `pytest.ini` is located.

### Module Not Found
Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Continuous Integration

For CI/CD pipelines, use:
```bash
python -m pytest --import-mode=importlib --tb=short -v --junitxml=test-results.xml
```

This generates a JUnit XML report that can be consumed by CI systems.

