-- CreateEnum
CREATE TYPE "EntityStatusEnum" AS ENUM ('PENDING', 'ACTIVE', 'SUSPENDED', 'CLOSED');

-- CreateEnum
CREATE TYPE "EntityTypeEnum" AS ENUM ('INDIVIDUAL', 'BUSINESS');

-- CreateEnum
CREATE TYPE "KycStatusEnum" AS ENUM ('PENDING', 'INITIATED', 'REVIEWING', 'APPROVED', 'ADDITIONAL_INFO_REQUIRED', 'REJECTED');

-- CreateEnum
CREATE TYPE "WebhookEventCategory" AS ENUM ('KYC', 'TRANSFER', 'PAYMENT', 'ALM', 'TELEPORT');

-- CreateEnum
CREATE TYPE "WebhookDeliveryStatusEnum" AS ENUM ('PENDING', 'SUCCESS', 'FAILED', 'RETRYING');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "entities" (
    "entity_id" UUID NOT NULL,
    "entity_type" "EntityTypeEnum" NOT NULL DEFAULT 'INDIVIDUAL',
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "email_verified" BOOLEAN DEFAULT false,
    "last_login_at" TIMESTAMP(3),
    "login_attempts" INTEGER DEFAULT 0,
    "locked_until" TIMESTAMP(3),
    "encrypted_data" BYTEA,
    "encryption_key_id" TEXT,
    "status" "EntityStatusEnum" NOT NULL DEFAULT 'PENDING',
    "created_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "entities_pkey" PRIMARY KEY ("entity_id")
);

-- CreateTable
CREATE TABLE "kyc_sessions" (
    "kyc_session_id" UUID NOT NULL,
    "entity_id" UUID NOT NULL,
    "routing_id" TEXT,
    "status" "KycStatusEnum" NOT NULL DEFAULT 'PENDING',
    "routing_enabled" BOOLEAN DEFAULT false,
    "initiated_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "rejection_reason" TEXT,
    "created_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "kyc_sessions_pkey" PRIMARY KEY ("kyc_session_id")
);

-- CreateTable
CREATE TABLE "kyc_documents" (
    "document_id" UUID NOT NULL,
    "kyc_session_id" UUID NOT NULL,
    "document_type" TEXT NOT NULL,
    "file_path" TEXT,
    "encrypted_data" BYTEA,
    "uploaded_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "kyc_documents_pkey" PRIMARY KEY ("document_id")
);

-- CreateTable
CREATE TABLE "webhook_events" (
    "event_id" UUID NOT NULL,
    "event_category" "WebhookEventCategory" NOT NULL,
    "event_type" TEXT NOT NULL,
    "event_status" TEXT,
    "entity_id" UUID,
    "kyc_session_id" UUID,
    "transfer_id" UUID,
    "alm_tx_id" UUID,
    "teleport_id" UUID,
    "event_payload" JSONB NOT NULL,
    "delivery_status" "WebhookDeliveryStatusEnum" NOT NULL DEFAULT 'PENDING',
    "delivery_attempts" INTEGER DEFAULT 0,
    "last_attempt_at" TIMESTAMP(3),
    "next_retry_at" TIMESTAMP(3),
    "http_status_code" INTEGER,
    "response_body" TEXT,
    "created_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_events_pkey" PRIMARY KEY ("event_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE UNIQUE INDEX "entities_email_key" ON "entities"("email");

-- AddForeignKey
ALTER TABLE "kyc_sessions" ADD CONSTRAINT "kyc_sessions_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("entity_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "kyc_documents" ADD CONSTRAINT "kyc_documents_kyc_session_id_fkey" FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("kyc_session_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("entity_id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_kyc_session_id_fkey" FOREIGN KEY ("kyc_session_id") REFERENCES "kyc_sessions"("kyc_session_id") ON DELETE SET NULL ON UPDATE CASCADE;
