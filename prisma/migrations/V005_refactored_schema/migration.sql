/*
  Warnings:

  - The values [PENDING] on the enum `KycStatusEnum` will be removed. If these variants are still used in the database, this will fail.
  - The values [PAYMENT,ALM,TELEPORT] on the enum `WebhookEventCategory` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `alm_tx_id` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `delivery_attempts` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `delivery_status` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `http_status_code` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `last_attempt_at` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `next_retry_at` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `response_body` on the `webhook_events` table. All the data in the column will be lost.
  - You are about to drop the column `transfer_id` on the `webhook_events` table. All the data in the column will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "KycStatusEnum_new" AS ENUM ('NOT_STARTED', 'INITIATED', 'REVIEWING', 'ADDITIONAL_INFO_REQUIRED', 'REJECTED', 'APPROVED');
ALTER TABLE "kyc_sessions" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "kyc_sessions" ALTER COLUMN "status" TYPE "KycStatusEnum_new" USING ("status"::text::"KycStatusEnum_new");
ALTER TYPE "KycStatusEnum" RENAME TO "KycStatusEnum_old";
ALTER TYPE "KycStatusEnum_new" RENAME TO "KycStatusEnum";
DROP TYPE "KycStatusEnum_old";
ALTER TABLE "kyc_sessions" ALTER COLUMN "status" SET DEFAULT 'NOT_STARTED';
COMMIT;

-- AlterEnum
BEGIN;
CREATE TYPE "WebhookEventCategory_new" AS ENUM ('KYC', 'TRANSFER', 'WEBHOOK');
ALTER TABLE "webhook_events" ALTER COLUMN "event_category" TYPE "WebhookEventCategory_new" USING ("event_category"::text::"WebhookEventCategory_new");
ALTER TYPE "WebhookEventCategory" RENAME TO "WebhookEventCategory_old";
ALTER TYPE "WebhookEventCategory_new" RENAME TO "WebhookEventCategory";
DROP TYPE "WebhookEventCategory_old";
COMMIT;

-- AlterTable
ALTER TABLE "kyc_sessions" ADD COLUMN     "kyc_link" TEXT,
ALTER COLUMN "status" SET DEFAULT 'NOT_STARTED';

-- AlterTable
ALTER TABLE "webhook_events" DROP COLUMN "alm_tx_id",
DROP COLUMN "delivery_attempts",
DROP COLUMN "delivery_status",
DROP COLUMN "http_status_code",
DROP COLUMN "last_attempt_at",
DROP COLUMN "next_retry_at",
DROP COLUMN "response_body",
DROP COLUMN "transfer_id";
