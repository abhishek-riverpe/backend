-- CreateEnum
CREATE TYPE "AccountStatusEnum" AS ENUM ('inactive', 'active');

-- CreateTable
CREATE TABLE "funding_accounts" (
    "funding_account_id" TEXT NOT NULL,
    "entity_id" TEXT NOT NULL,
    "jurisdiction_id" TEXT NOT NULL,
    "provider_id" TEXT NOT NULL,
    "status" "AccountStatusEnum" NOT NULL DEFAULT 'inactive',
    "currency" TEXT NOT NULL,
    "bank_name" TEXT NOT NULL,
    "bank_address" TEXT NOT NULL,
    "bank_routing_number" TEXT NOT NULL,
    "bank_account_number" TEXT NOT NULL,
    "bank_beneficiary_name" TEXT NOT NULL,
    "bank_beneficiary_address" TEXT NOT NULL,
    "payment_rail" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "funding_accounts_pkey" PRIMARY KEY ("funding_account_id")
);
