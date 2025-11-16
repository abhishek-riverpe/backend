-- CreateEnum
CREATE TYPE "EntityStatusEnum" AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'CLOSED');

-- CreateEnum
CREATE TYPE "EntityTypeEnum" AS ENUM ('INDIVIDUAL', 'BUSINESS');

-- CreateEnum
CREATE TYPE "KycStatusEnum" AS ENUM ('NOT_STARTED', 'INITIATED', 'REVIEWING', 'ADDITIONAL_INFO_REQUIRED', 'REJECTED', 'APPROVED');

-- CreateEnum
CREATE TYPE "WebhookEventCategory" AS ENUM ('KYC', 'TRANSFER', 'WEBHOOK');

-- CreateEnum
CREATE TYPE "WebhookDeliveryStatusEnum" AS ENUM ('PENDING', 'SUCCESS', 'FAILED', 'RETRYING');

-- CreateEnum
CREATE TYPE "OtpTypeEnum" AS ENUM ('PHONE_VERIFICATION', 'EMAIL_VERIFICATION', 'PASSWORD_RESET');

-- CreateEnum
CREATE TYPE "OtpStatusEnum" AS ENUM ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED');

-- CreateEnum
CREATE TYPE "SessionStatusEnum" AS ENUM ('ACTIVE', 'EXPIRED', 'LOGGED_OUT', 'REVOKED');

-- CreateEnum
CREATE TYPE "LoginMethodEnum" AS ENUM ('EMAIL_PASSWORD', 'GOOGLE_OAUTH', 'PHONE_OTP', 'APPLE_ID');

-- CreateEnum
CREATE TYPE "AccountStatusEnum" AS ENUM ('INACTIVE', 'ACTIVE');

-- CreateTable
CREATE TABLE "entities" (
    "id" UUID NOT NULL,
    "zynk_entity_id" TEXT,
    "entity_type" "EntityTypeEnum" NOT NULL DEFAULT 'INDIVIDUAL',
    "email" TEXT NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "date_of_birth" TIMESTAMP(3),
    "nationality" TEXT,
    "phone_number" TEXT,
    "country_code" TEXT,
    "email_verified" BOOLEAN DEFAULT false,
    "last_login_at" TIMESTAMP(3),
    "login_attempts" INTEGER DEFAULT 0,
    "locked_until" TIMESTAMP(3),
    "encrypted_data" BYTEA,
    "encryption_key_id" TEXT,
    "status" "EntityStatusEnum" NOT NULL DEFAULT 'PENDING',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "entities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "kyc_sessions" (
    "id" UUID NOT NULL,
    "entity_id" UUID NOT NULL,
    "routing_id" TEXT,
    "status" "KycStatusEnum" NOT NULL DEFAULT 'NOT_STARTED',
    "kyc_link" TEXT,
    "routing_enabled" BOOLEAN DEFAULT false,
    "initiated_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "rejection_reason" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "kyc_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "kyc_documents" (
    "id" UUID NOT NULL,
    "kyc_session_id" UUID NOT NULL,
    "document_type" TEXT NOT NULL,
    "file_path" TEXT,
    "encrypted_data" BYTEA,
    "uploaded_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "kyc_documents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_events" (
    "id" UUID NOT NULL,
    "event_category" "WebhookEventCategory" NOT NULL,
    "event_type" TEXT NOT NULL,
    "event_status" TEXT,
    "entity_id" UUID,
    "kyc_session_id" UUID,
    "teleport_id" UUID,
    "event_payload" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "webhook_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "otp_verifications" (
    "id" UUID NOT NULL,
    "phone_number" TEXT,
    "email" TEXT,
    "country_code" TEXT DEFAULT '+1',
    "otp_code" TEXT NOT NULL,
    "otp_type" "OtpTypeEnum" NOT NULL DEFAULT 'PHONE_VERIFICATION',
    "status" "OtpStatusEnum" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 3,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "verified_at" TIMESTAMP(3),
    "ip_address" TEXT,
    "user_agent" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "otp_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "login_sessions" (
    "id" UUID NOT NULL,
    "entity_id" UUID NOT NULL,
    "session_token" TEXT NOT NULL,
    "login_method" "LoginMethodEnum" NOT NULL DEFAULT 'EMAIL_PASSWORD',
    "status" "SessionStatusEnum" NOT NULL DEFAULT 'ACTIVE',
    "ip_address" TEXT,
    "user_agent" TEXT,
    "device_type" TEXT,
    "device_name" TEXT,
    "os_name" TEXT,
    "os_version" TEXT,
    "browser_name" TEXT,
    "browser_version" TEXT,
    "app_version" TEXT,
    "country" TEXT,
    "city" TEXT,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "login_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_activity_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "logout_at" TIMESTAMP(3),
    "expires_at" TIMESTAMP(3) NOT NULL,
    "is_suspicious" BOOLEAN NOT NULL DEFAULT false,
    "mfa_verified" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "login_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "funding_accounts" (
    "id" UUID NOT NULL,
    "entity_id" UUID NOT NULL,
    "jurisdiction_id" TEXT NOT NULL,
    "provider_id" TEXT NOT NULL,
    "status" "AccountStatusEnum" NOT NULL DEFAULT 'INACTIVE',
    "currency" TEXT NOT NULL,
    "bank_name" TEXT NOT NULL,
    "bank_address" TEXT NOT NULL,
    "bank_routing_number" TEXT NOT NULL,
    "bank_account_number" TEXT NOT NULL,
    "bank_beneficiary_name" TEXT NOT NULL,
    "bank_beneficiary_address" TEXT NOT NULL,
    "payment_rail" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "funding_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "entities_zynk_entity_id_key" ON "entities"("zynk_entity_id");

-- CreateIndex
CREATE UNIQUE INDEX "entities_email_key" ON "entities"("email");

-- CreateIndex
CREATE INDEX "otp_verifications_phone_number_status_idx" ON "otp_verifications"("phone_number", "status");

-- CreateIndex
CREATE INDEX "otp_verifications_email_status_idx" ON "otp_verifications"("email", "status");

-- CreateIndex
CREATE INDEX "otp_verifications_expires_at_idx" ON "otp_verifications"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "login_sessions_session_token_key" ON "login_sessions"("session_token");

-- CreateIndex
CREATE INDEX "login_sessions_entity_id_status_idx" ON "login_sessions"("entity_id", "status");

-- CreateIndex
CREATE INDEX "login_sessions_session_token_idx" ON "login_sessions"("session_token");

-- CreateIndex
CREATE INDEX "login_sessions_expires_at_idx" ON "login_sessions"("expires_at");

-- CreateIndex
CREATE INDEX "login_sessions_login_at_idx" ON "login_sessions"("login_at");

-- AddForeignKey
ALTER TABLE "kyc_sessions" ADD CONSTRAINT "kyc_sessions_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "kyc_documents" ADD CONSTRAINT "kyc_documents_kyc_session_id_fkey" FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_kyc_session_id_fkey" FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "login_sessions" ADD CONSTRAINT "login_sessions_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "funding_accounts" ADD CONSTRAINT "funding_accounts_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE CASCADE ON UPDATE CASCADE;
