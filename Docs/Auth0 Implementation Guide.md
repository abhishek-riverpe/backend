# Auth0 Implementation Guide

## Architecture Overview

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  React Native   │         │     Auth0       │         │    FastAPI      │
│     (Client)    │         │   (Identity)    │         │    (Backend)    │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │ 1. Universal Login        │                           │
         │   (PKCE Flow)             │                           │
         │──────────────────────────>│                           │
         │                           │                           │
         │ 2. access_token (JWT)     │                           │
         │   + id_token              │                           │
         │<──────────────────────────│                           │
         │                           │                           │
         │ 3. API Request            │                           │
         │   Authorization: Bearer <access_token>                │
         │──────────────────────────────────────────────────────>│
         │                           │                           │
         │                           │ 4. Verify JWT (JWKS)      │
         │                           │<──────────────────────────│
         │                           │──────────────────────────>│
         │                           │                           │
         │ 5. Response               │                           │
         │<──────────────────────────────────────────────────────│
```

---

## Key Concepts

### Token Flow
- Auth0 returns tokens to the RN app:
  - `access_token` (JWT) → sent to backend
  - `id_token` (JWT) → frontend only
- RN stores tokens securely (Keychain / SecureStore)
- RN sends API requests with: `Authorization: Bearer <access_token>`

### PKCE
- Used only between RN and Auth0
- Protects authorization code exchange
- Backend is not involved in PKCE

### Backend (FastAPI)
- No login/signup APIs
- Only verifies JWT access tokens
- Uses Auth0 JWKS to verify: signature (RS256), issuer, audience, expiry
- Extracts `sub` from JWT as user identity
- Uses Just-In-Time user creation on first request

---

## Auth Flow

| Step | Actor | Action |
|------|-------|--------|
| 1 | RN App | Opens Auth0 Universal Login (email/pwd or Google) |
| 2 | Auth0 | Returns `access_token` + `id_token` to RN App |
| 3 | RN App | Stores tokens securely (Keychain/SecureStore) |
| 4 | RN App | Calls `GET /api/v1/users/me` with Bearer token |
| 5 | Backend | Verifies JWT, creates user (JIT), returns profile |
| 6 | RN App | If status=`REGISTERED`, show profile completion form |
| 7 | RN App | Calls `POST /api/v1/users/me/profile` with profile data |
| 8 | Backend | Creates Zynk entity, returns status=`PENDING` |
| 9 | RN App | Redirect to KYC flow |

---

## User Status Flow

```
REGISTERED ──> PENDING ──> ACTIVE
     │             │           │
     │             │           └── Fully onboarded, all features available
     │             │
     │             └── Profile complete, Zynk entity created, KYC in progress
     │
     └── Just logged in via Auth0, needs to complete profile
```

---

## Backend API Endpoints

### Base URL: `/api/v1/users`

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/me` | GET | Required | Get current user profile (JIT creates user on first call) |
| `/me/profile` | POST | Required | Complete profile + create Zynk entity |
| `/me` | PATCH | Required | Update profile fields |
| `/me/onboarding-status` | GET | Required | Get onboarding progress |

---

## API Request/Response Examples

### 1. GET /api/v1/users/me

**Request:**
```http
GET /api/v1/users/me HTTP/1.1
Host: api.riverpe.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (New User - REGISTERED):**
```json
{
  "success": true,
  "message": "User profile retrieved successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "auth0_sub": "auth0|123456789",
    "email": "user@example.com",
    "email_verified": true,
    "first_name": null,
    "last_name": null,
    "phone_number": null,
    "country_code": null,
    "date_of_birth": null,
    "nationality": null,
    "entity_type": "INDIVIDUAL",
    "status": "REGISTERED",
    "zynk_entity_id": null,
    "last_login_at": "2025-12-16T10:30:00Z",
    "created_at": "2025-12-16T10:30:00Z",
    "updated_at": "2025-12-16T10:30:00Z"
  },
  "error": null,
  "meta": null
}
```

**Response (Existing User - ACTIVE):**
```json
{
  "success": true,
  "message": "User profile retrieved successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "auth0_sub": "auth0|123456789",
    "email": "user@example.com",
    "email_verified": true,
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "9876543210",
    "country_code": "+1",
    "date_of_birth": "1990-05-15",
    "nationality": "US",
    "entity_type": "INDIVIDUAL",
    "status": "ACTIVE",
    "zynk_entity_id": "zynk_entity_abc123",
    "last_login_at": "2025-12-16T10:30:00Z",
    "created_at": "2025-12-10T08:00:00Z",
    "updated_at": "2025-12-16T10:30:00Z"
  },
  "error": null,
  "meta": null
}
```

---

### 2. GET /api/v1/users/me/onboarding-status

**Response:**
```json
{
  "success": true,
  "message": "Onboarding status retrieved successfully",
  "data": {
    "status": "REGISTERED",
    "steps": {
      "auth": { "complete": true },
      "profile": {
        "complete": false,
        "required_fields": ["first_name", "last_name", "date_of_birth", "nationality", "phone_number", "country_code"]
      },
      "zynk_entity": { "complete": false },
      "kyc": { "complete": false, "status": null }
    },
    "next_action": "COMPLETE_PROFILE"
  },
  "error": null,
  "meta": null
}
```

**Possible `next_action` values:**
- `COMPLETE_PROFILE` - User needs to fill profile form
- `COMPLETE_KYC` - User needs to complete KYC verification
- `NONE` - User is fully onboarded

---

### 3. POST /api/v1/users/me/profile

**Request:**
```http
POST /api/v1/users/me/profile HTTP/1.1
Host: api.riverpe.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "date_of_birth": "1990-05-15",
  "nationality": "US",
  "phone_number": "9876543210",
  "country_code": "+1",
  "entity_type": "INDIVIDUAL"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Profile completed successfully. Please proceed with KYC verification.",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "auth0_sub": "auth0|123456789",
    "email": "user@example.com",
    "email_verified": true,
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "9876543210",
    "country_code": "+1",
    "date_of_birth": "1990-05-15",
    "nationality": "US",
    "entity_type": "INDIVIDUAL",
    "status": "PENDING",
    "zynk_entity_id": "zynk_entity_abc123",
    "last_login_at": "2025-12-16T10:30:00Z",
    "created_at": "2025-12-16T10:30:00Z",
    "updated_at": "2025-12-16T10:35:00Z"
  },
  "error": null,
  "meta": null
}
```

**Response (Error - Already Submitted):**
```json
{
  "detail": "Profile already completed. Current status: PENDING"
}
```

**Validation Rules:**

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `first_name` | string | Yes | 1-60 chars |
| `last_name` | string | Yes | 1-60 chars |
| `date_of_birth` | string | Yes | Format: `YYYY-MM-DD` |
| `nationality` | string | Yes | 2-3 chars (ISO country code) |
| `phone_number` | string | Yes | 5-20 chars |
| `country_code` | string | Yes | 1-5 chars (e.g., `+1`, `+91`) |
| `entity_type` | enum | No | `INDIVIDUAL` (default) or `BUSINESS` |

---

### 4. PATCH /api/v1/users/me

**Request:**
```http
PATCH /api/v1/users/me HTTP/1.1
Host: api.riverpe.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "phone_number": "1234567890",
  "country_code": "+44"
}
```

**Note:** `first_name` and `last_name` can only be changed when status is `REGISTERED`.

---

## Frontend Implementation Guide

### 1. Auth0 Configuration (React Native)

```javascript
// auth0Config.js
export const auth0Config = {
  domain: 'your-tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  audience: 'https://api.riverpe.com', // Must match backend AUTH0_AUDIENCE
  scope: 'openid profile email offline_access',
};
```

### 2. Login Flow

```javascript
// Using react-native-auth0
import Auth0 from 'react-native-auth0';

const auth0 = new Auth0({
  domain: auth0Config.domain,
  clientId: auth0Config.clientId,
});

// Login
const login = async () => {
  try {
    const credentials = await auth0.webAuth.authorize({
      scope: auth0Config.scope,
      audience: auth0Config.audience,
    });

    // credentials.accessToken - Send to backend
    // credentials.idToken - Frontend only (user info)
    // credentials.refreshToken - For refreshing access token

    await SecureStore.setItemAsync('access_token', credentials.accessToken);
    await SecureStore.setItemAsync('refresh_token', credentials.refreshToken);

    // Fetch user profile from backend
    const userProfile = await fetchUserProfile(credentials.accessToken);

    // Navigate based on status
    if (userProfile.status === 'REGISTERED') {
      navigation.navigate('CompleteProfile');
    } else if (userProfile.status === 'PENDING') {
      navigation.navigate('KYCFlow');
    } else {
      navigation.navigate('Home');
    }
  } catch (error) {
    console.error('Login failed:', error);
  }
};
```

### 3. API Client Setup

```javascript
// apiClient.js
import * as SecureStore from 'expo-secure-store';

const API_BASE_URL = 'https://api.riverpe.com/api/v1';

const apiClient = async (endpoint, options = {}) => {
  const accessToken = await SecureStore.getItemAsync('access_token');

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      ...options.headers,
    },
  });

  if (response.status === 401) {
    // Token expired - try refresh or re-login
    await refreshTokenOrLogout();
    throw new Error('Session expired');
  }

  return response.json();
};

// API Functions
export const getUserProfile = () => apiClient('/users/me');

export const getOnboardingStatus = () => apiClient('/users/me/onboarding-status');

export const completeProfile = (profileData) => apiClient('/users/me/profile', {
  method: 'POST',
  body: JSON.stringify(profileData),
});

export const updateProfile = (updates) => apiClient('/users/me', {
  method: 'PATCH',
  body: JSON.stringify(updates),
});
```

### 4. Token Refresh

```javascript
// tokenRefresh.js
const refreshAccessToken = async () => {
  const refreshToken = await SecureStore.getItemAsync('refresh_token');

  if (!refreshToken) {
    throw new Error('No refresh token');
  }

  const response = await auth0.auth.refreshToken({
    refreshToken,
    scope: auth0Config.scope,
  });

  await SecureStore.setItemAsync('access_token', response.accessToken);

  return response.accessToken;
};
```

### 5. App Navigation Logic

```javascript
// AppNavigator.js
const AppNavigator = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [userStatus, setUserStatus] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    checkAuthState();
  }, []);

  const checkAuthState = async () => {
    try {
      const token = await SecureStore.getItemAsync('access_token');

      if (!token) {
        setIsAuthenticated(false);
        setIsLoading(false);
        return;
      }

      // Verify token and get user status
      const profile = await getUserProfile();
      setUserStatus(profile.data.status);
      setIsAuthenticated(true);
    } catch (error) {
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return <SplashScreen />;
  }

  return (
    <NavigationContainer>
      {!isAuthenticated ? (
        <AuthStack />
      ) : userStatus === 'REGISTERED' ? (
        <OnboardingStack />
      ) : userStatus === 'PENDING' ? (
        <KYCStack />
      ) : (
        <MainStack />
      )}
    </NavigationContainer>
  );
};
```

### 6. Complete Profile Screen

```javascript
// CompleteProfileScreen.js
const CompleteProfileScreen = () => {
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    date_of_birth: '',
    nationality: '',
    phone_number: '',
    country_code: '+1',
    entity_type: 'INDIVIDUAL',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await completeProfile(formData);

      if (response.success) {
        // Navigate to KYC flow
        navigation.replace('KYCFlow');
      } else {
        setError(response.message);
      }
    } catch (err) {
      setError('Failed to complete profile. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <View>
      <TextInput
        placeholder="First Name"
        value={formData.first_name}
        onChangeText={(text) => setFormData({...formData, first_name: text})}
      />
      <TextInput
        placeholder="Last Name"
        value={formData.last_name}
        onChangeText={(text) => setFormData({...formData, last_name: text})}
      />
      {/* Date picker for date_of_birth */}
      {/* Country picker for nationality */}
      {/* Phone input with country code */}

      <Button title="Continue" onPress={handleSubmit} disabled={loading} />
      {error && <Text style={styles.error}>{error}</Text>}
    </View>
  );
};
```

---

## Status Enum Reference

```typescript
enum UserStatusEnum {
  REGISTERED = 'REGISTERED',  // Auth0 login complete, needs profile
  PENDING = 'PENDING',        // Profile complete, KYC in progress
  ACTIVE = 'ACTIVE',          // Fully onboarded
  SUSPENDED = 'SUSPENDED',    // Account suspended
  CLOSED = 'CLOSED',          // Account closed
}

enum EntityTypeEnum {
  INDIVIDUAL = 'INDIVIDUAL',
  BUSINESS = 'BUSINESS',
}

enum NextActionEnum {
  COMPLETE_PROFILE = 'COMPLETE_PROFILE',
  COMPLETE_KYC = 'COMPLETE_KYC',
  NONE = 'NONE',
}
```

---

## Auth0 Dashboard Setup

### 1. Create API
- **Name:** RiverPe API
- **Identifier:** `https://api.riverpe.com`
- **Signing Algorithm:** RS256

### 2. Create Native Application
- **Type:** Native
- **Allowed Callback URLs:** `com.riverpe.app://callback`
- **Allowed Logout URLs:** `com.riverpe.app://logout`

### 3. Enable Connections
- Database (Email/Password)
- Google OAuth

### 4. Add Custom Action (Login Flow)
```javascript
exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('email', event.user.email);
  api.accessToken.setCustomClaim('email_verified', event.user.email_verified);
};
```

---

## Backend Environment Variables

```env
# Auth0 (Required)
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_AUDIENCE=https://api.riverpe.com

# Existing (already configured)
DATABASE_URL=postgresql://...
ZYNK_BASE_URL=...
ZYNK_API_KEY=...
ZYNK_DEFAULT_ROUTING_ID=...
```

---

## Files Created/Modified

| File | Purpose |
|------|---------|
| `app/core/config.py` | Added Auth0 settings |
| `app/core/auth0.py` | JWT verification + JIT user creation |
| `app/schemas/user.py` | Request/response models |
| `app/routers/user_router.py` | User profile endpoints |
| `app/main.py` | Router registration |
| `prisma/schema.prisma` | `UserStatusEnum` with REGISTERED state |

---

## Error Responses

### 401 Unauthorized
```json
{
  "detail": "Authentication required"
}
```

### 400 Bad Request
```json
{
  "detail": "Profile already completed. Current status: PENDING"
}
```

### 502 Bad Gateway (Zynk Error)
```json
{
  "detail": "Failed to get entity ID from verification service"
}
```
