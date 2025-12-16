---
  Redundant APIs (Can Be Removed/Consolidated)

  [FIXED] 1. KYC Link Duplicate ⚠️ Clear Redundancy

  | Endpoint             | Issue              |
  |----------------------|--------------------|
  | GET /api/v1/kyc/     | Same exact handler |
  | GET /api/v1/kyc/link | Same exact handler |

  Evidence: kyc_router.py:106-107 - Both routes point to the exact same function:
  @router.get("", response_model=KycLinkResponse, ...)
  @router.get("/link", response_model=KycLinkResponse, ...)
  async def get_kyc_link(...):
  Recommendation: Remove /link - keep just GET /api/v1/kyc

  ---
  [Fixed] 2. OTP Resend Endpoints ⚠️ 100% Duplicate

  | Endpoint                      | Issue                       |
  |-------------------------------|-----------------------------|
  | POST /api/v1/otp/resend       | Just calls send_otp()       |
  | POST /api/v1/otp/email/resend | Just calls send_email_otp() |

  Evidence: otp_router.py:92-94 and otp_router.py:169-171:
  @router.post("/resend")
  async def resend_otp(request: OtpSendRequest):
      return await send_otp(request)  # Literally just forwards

  @router.post("/email/resend")
  async def resend_email_otp(request: EmailOtpSendRequest):
      return await send_email_otp(request)  # Same thing
  Recommendation: Remove both /resend endpoints. Add resend: bool parameter to /send endpoints if needed.

  ---
  3. Wallet Details Overlap ⚠️ Confusing

  | Endpoint                 | Source         |
  |--------------------------|----------------|
  | GET /api/v1/wallets/user | Local database |
  | GET /api/v1/wallets/     | Zynk API       |

  Issue: Both return wallet details but from different sources. Confusing for API consumers.
  Recommendation: Consolidate into single endpoint with ?source=local|zynk parameter, or rename for clarity.

  ---
  Summary of Removable Endpoints

  | Count | Endpoints                                                                                       |
  |-------|-------------------------------------------------------------------------------------------------|
  | 4     | /api/v1/kyc/link, /api/v1/otp/resend, /api/v1/otp/email/resend, one of the wallet GET endpoints |

  Summary

  | Category                  | Count       |
  |---------------------------|-------------|
  | Redundant (remove)        | 4 endpoints |


