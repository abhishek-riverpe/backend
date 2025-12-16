 Complete Onboarding Flow

  ┌──────────────────────────────────────────────────────────────────────┐
  │                         ONBOARDING FLOW                               │
  └──────────────────────────────────────────────────────────────────────┘

  Step 1: Auth0 Login
  ─────────────────────
    RN App ──Auth0──> Backend (GET /users/me)
                           │
                           ▼
                      JIT Create Entity
                      status: REGISTERED
                      zynk_entity_id: null
                           │
                           ▼
                      Return { status: "REGISTERED", next: "COMPLETE_PROFILE" }


  Step 2: Complete Profile + Create Zynk Entity
  ──────────────────────────────────────────────
    RN App ──POST /users/me/profile──> Backend
             {
               first_name, last_name,
               date_of_birth, nationality,
               entity_type, ...
             }
                           │
                           ▼
                      Validate required fields
                           │
                           ▼
                      Call Zynk API: Create Entity
                           │
                           ▼
                      Update entity:
                      - zynk_entity_id: "zynk_..."
                      - status: PENDING
                           │
                           ▼
                      Return { status: "PENDING", next: "COMPLETE_KYC" }


  Step 3: KYC (via webhook)
  ─────────────────────────
    Zynk ──Webhook──> Backend (POST /webhooks/zynk)
                           │
                           ▼
                      KYC Approved?
                      - status: ACTIVE
                           │
                           ▼
                      User fully onboarded

  ---
  API Summary

  | Endpoint          | Method | Input          | Action                        | Status Transition     |
  |-------------------|--------|----------------|-------------------------------|-----------------------|
  | /users/me         | GET    | -              | Get or create user            | → REGISTERED (if new) |
  | /users/me/profile | POST   | profile fields | Validate + Create Zynk entity | REGISTERED → PENDING  |
  | /users/me         | PATCH  | partial fields | Update profile                | No change             |
  | /webhooks/zynk    | POST   | KYC event      | Handle KYC result             | PENDING → ACTIVE      |

  ---
  Validation Logic

  # POST /users/me/profile - Required fields for Zynk entity creation
  REQUIRED_PROFILE_FIELDS = [
      "first_name",
      "last_name",
      "date_of_birth",
      "nationality",
      "entity_type",  # INDIVIDUAL or BUSINESS
  ]

  # Only allow if status == REGISTERED
  if user.status != UserStatusEnum.REGISTERED:
      raise HTTPException(400, "Profile already submitted")

