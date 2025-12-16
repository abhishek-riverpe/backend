# Core Health & Status - [Working]

  | Method | Path       | Description                          |
  |--------|------------|--------------------------------------|
  | GET    | /          | Root - "NeoBank API is running"      |
  | GET    | /health    | Health check                         |
  | GET    | /readiness | Readiness check with DB verification |
  | GET    | /liveness  | Liveness check                       |

  Authentication (/api/v1/auth)

  | Method | Path                     | Description                 |
  |--------|--------------------------|-----------------------------|
  | POST   | /check-captcha-required  | Check if CAPTCHA needed     | [Working]
  | POST   | /check-email             | Validate email availability | [Working]
  | POST   | /signup                  | User registration           | [Working]
  | POST   | /signin                  | User login                  | [Working]
  | POST   | /forgot-password/confirm | Confirm password reset      | [Working]
  | POST   | /refresh                 | Refresh access token        | [Working]
  | POST   | /logout                  | Logout user                 | [Working]
  | POST   | /change-password         | Change password             | [Working]
  | GET    | /ping                    | Validate bearer token       | [Working]
  | POST   | /logout-all              | Logout all devices          | [Working]

  Google OAuth (/auth)

  | Method | Path             | Description              |
  |--------|------------------|--------------------------|
  | GET    | /google          | Google OAuth redirect    |
  | GET    | /google/callback | OAuth callback handler   |
  | POST   | /google/exchange | Exchange code for tokens |

  Entity/Transformer (/api/v1/transformer/entity)

  | Method | Path                                       | Description            |
  |--------|--------------------------------------------|------------------------|
  | POST   | /                                          | Create external entity |
  | GET    | /entities                                  | Get all entities       |
  | GET    | /{entity_id}                               | Get entity by ID       |
  | GET    | /email/{email}                             | Get entity by email    |
  | GET    | /kyc/requirements/{user_id}                | Get KYC requirements   |
  | POST   | /kyc/{entity_id}/{routing_id}              | Upload KYC documents   |
  | GET    | /kyc/{entity_id}                           | Get KYC status         |
  | GET    | /kyc/requirements/{entity_id}/{routing_id} | Get KYC requirements   |
  | GET    | /{entity_id}/kyc/documents                 | Get KYC documents      |

  KYC (/api/v1/kyc)

  | Method | Path    | Description              |
  |--------|---------|--------------------------|
  | GET    | /status | Get KYC status           | [Working]
  | GET    | /       | Get KYC link             |   
  | GET    | /link   | Get KYC link (alternate) |

  OTP (/api/v1/otp)

  | Method | Path          | Description      |
  |--------|---------------|------------------|
  | POST   | /send         | Send SMS OTP     | [Working]
  | POST   | /verify       | Verify SMS OTP   | [Working]
  | POST   | /resend       | Resend SMS OTP   | [Working]
  | POST   | /email/send   | Send email OTP   | [Working] [Email_from_Divyansh]
  | POST   | /email/verify | Verify email OTP | [Working]
  | POST   | /email/resend | Resend email OTP | [Working]

  Funding Account (/api/v1/account)

  | Method | Path            | Description            |
  |--------|-----------------|------------------------|
  | GET    | /funding        | Get funding account    | [Working]
  | POST   | /funding/create | Create funding account | 

  CAPTCHA (/api/v1/captcha)

  | Method | Path      | Description            |
  |--------|-----------|------------------------|
  | POST   | /generate | Generate CAPTCHA image |
  | POST   | /validate | Validate CAPTCHA code  |

  Teleport (/api/v1/teleport)

  | Method | Path | Description          |
  |--------|------|----------------------|
  | GET    | /    | Get teleport details |
  | POST   | /    | Create teleport      |

  Wallet (/api/v1/wallets)

  | Method | Path                                | Description                    |
  |--------|-------------------------------------|--------------------------------|
  | POST   | /register-auth                      | Register wallet authentication |
  | POST   | /generate-keypair                   | Generate keypair               |
  | POST   | /initiate-otp                       | Initiate OTP for wallet        |
  | POST   | /start-session                      | Start wallet session           |
  | POST   | /decrypt-bundle                     | Decrypt credential bundle      |
  | POST   | /prepare                            | Prepare wallet creation        |
  | GET    | /user                               | Get user wallet                |
  | GET    | /                                   | Get wallet details             |
  | GET    | /balances                           | Get wallet balances            |
  | GET    | /{wallet_id}/{address}/transactions | Get wallet transactions        |
  | POST   | /sign-payload                       | Sign payload                   |
  | POST   | /submit                             | Submit wallet creation         |
  | POST   | /{wallet_id}/accounts/prepare       | Prepare account creation       |
  | POST   | /accounts/submit                    | Submit account creation        |

  Webhooks (/api/v1/webhooks)

  | Method | Path  | Description           |
  |--------|-------|-----------------------|
  | POST   | /zynk | Receive Zynk webhooks |

  ---
  Summary

  - Total Endpoints: 62
  - 10 Router Modules: Auth, Google OAuth, Transformer/Entity, KYC, OTP, Funding Account, CAPTCHA, Teleport, Wallet, Webhooks
  - Key Features: Rate limiting (3-60/min), JWT authentication, KYC integration, Zynk Labs API integration, file uploads, webhook signature verification