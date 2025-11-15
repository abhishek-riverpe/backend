-- Migration: Standardize primary keys to 'id'
-- This migration renames all primary key columns from table_id to 'id'

BEGIN;

-- ============================================
-- STEP 1: DROP ALL FOREIGN KEY CONSTRAINTS FIRST
-- ============================================
-- We need to drop foreign keys before we can drop primary keys

-- Drop foreign keys referencing entities.entity_id
ALTER TABLE "kyc_sessions" DROP CONSTRAINT IF EXISTS "kyc_sessions_entity_id_fkey";
ALTER TABLE "webhook_events" DROP CONSTRAINT IF EXISTS "webhook_events_entity_id_fkey";
ALTER TABLE "login_sessions" DROP CONSTRAINT IF EXISTS "login_sessions_entity_id_fkey";

-- Drop foreign keys referencing kyc_sessions.kyc_session_id
ALTER TABLE "kyc_documents" DROP CONSTRAINT IF EXISTS "kyc_documents_kyc_session_id_fkey";
ALTER TABLE "webhook_events" DROP CONSTRAINT IF EXISTS "webhook_events_kyc_session_id_fkey";

-- ============================================
-- STEP 2: ENTITIES TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "entities" ADD COLUMN "id" UUID;

-- Copy data from entity_id to id (cast to UUID if needed)
UPDATE "entities" SET "id" = "entity_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "entities" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint (now safe since FKs are dropped)
ALTER TABLE "entities" DROP CONSTRAINT "entities_pkey";

-- Create new primary key on id
ALTER TABLE "entities" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 3: KYC_SESSIONS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "kyc_sessions" ADD COLUMN "id" UUID;

-- Copy data from kyc_session_id to id (cast to UUID if needed)
UPDATE "kyc_sessions" SET "id" = "kyc_session_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "kyc_sessions" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "kyc_sessions" DROP CONSTRAINT "kyc_sessions_pkey";

-- Create new primary key on id
ALTER TABLE "kyc_sessions" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 4: KYC_DOCUMENTS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "kyc_documents" ADD COLUMN "id" UUID;

-- Copy data from document_id to id (cast to UUID if needed)
UPDATE "kyc_documents" SET "id" = "document_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "kyc_documents" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "kyc_documents" DROP CONSTRAINT "kyc_documents_pkey";

-- Create new primary key on id
ALTER TABLE "kyc_documents" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 5: WEBHOOK_EVENTS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "webhook_events" ADD COLUMN "id" UUID;

-- Copy data from event_id to id (cast to UUID if needed)
UPDATE "webhook_events" SET "id" = "event_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "webhook_events" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "webhook_events" DROP CONSTRAINT "webhook_events_pkey";

-- Create new primary key on id
ALTER TABLE "webhook_events" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 6: OTP_VERIFICATIONS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "otp_verifications" ADD COLUMN "id" UUID;

-- Copy data from otp_id to id (cast to UUID if needed)
UPDATE "otp_verifications" SET "id" = "otp_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "otp_verifications" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "otp_verifications" DROP CONSTRAINT "otp_verifications_pkey";

-- Create new primary key on id
ALTER TABLE "otp_verifications" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 7: LOGIN_SESSIONS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "login_sessions" ADD COLUMN "id" UUID;

-- Copy data from session_id to id (cast to UUID if needed)
UPDATE "login_sessions" SET "id" = "session_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "login_sessions" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "login_sessions" DROP CONSTRAINT "login_sessions_pkey";

-- Create new primary key on id
ALTER TABLE "login_sessions" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 8: FUNDING_ACCOUNTS TABLE
-- ============================================
-- Add new id column (nullable first)
ALTER TABLE "funding_accounts" ADD COLUMN "id" UUID;

-- Copy data from funding_account_id to id (cast TEXT to UUID)
UPDATE "funding_accounts" SET "id" = "funding_account_id"::UUID;

-- Make id NOT NULL
ALTER TABLE "funding_accounts" ALTER COLUMN "id" SET NOT NULL;

-- Drop old primary key constraint
ALTER TABLE "funding_accounts" DROP CONSTRAINT "funding_accounts_pkey";

-- Create new primary key on id
ALTER TABLE "funding_accounts" ADD PRIMARY KEY ("id");

-- ============================================
-- STEP 9: RECREATE FOREIGN KEY CONSTRAINTS
-- ============================================
-- Now recreate foreign keys pointing to the new id columns

-- kyc_sessions references entities.id
ALTER TABLE "kyc_sessions" ADD CONSTRAINT "kyc_sessions_entity_id_fkey" 
    FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- kyc_documents references kyc_sessions.id
ALTER TABLE "kyc_documents" ADD CONSTRAINT "kyc_documents_kyc_session_id_fkey" 
    FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- webhook_events references entities.id
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_entity_id_fkey" 
    FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- webhook_events references kyc_sessions.id
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_kyc_session_id_fkey" 
    FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- login_sessions references entities.id
ALTER TABLE "login_sessions" ADD CONSTRAINT "login_sessions_entity_id_fkey" 
    FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ============================================
-- STEP 10: DROP OLD PRIMARY KEY COLUMNS
-- ============================================
-- Now safe to drop old columns since all foreign keys are updated

ALTER TABLE "entities" DROP COLUMN "entity_id";
ALTER TABLE "kyc_sessions" DROP COLUMN "kyc_session_id";
ALTER TABLE "kyc_documents" DROP COLUMN "document_id";
ALTER TABLE "webhook_events" DROP COLUMN "event_id";
ALTER TABLE "otp_verifications" DROP COLUMN "otp_id";
ALTER TABLE "login_sessions" DROP COLUMN "session_id";
ALTER TABLE "funding_accounts" DROP COLUMN "funding_account_id";

COMMIT;