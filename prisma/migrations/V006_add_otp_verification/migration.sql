-- CreateEnum
CREATE TYPE "OtpTypeEnum" AS ENUM ('PHONE_VERIFICATION', 'EMAIL_VERIFICATION', 'PASSWORD_RESET');

-- CreateEnum
CREATE TYPE "OtpStatusEnum" AS ENUM ('PENDING', 'VERIFIED', 'EXPIRED', 'FAILED');

-- CreateTable
CREATE TABLE "otp_verifications" (
    "otp_id" UUID NOT NULL,
    "phone_number" TEXT NOT NULL,
    "country_code" TEXT NOT NULL DEFAULT '+1',
    "otp_code" TEXT NOT NULL,
    "otp_type" "OtpTypeEnum" NOT NULL DEFAULT 'PHONE_VERIFICATION',
    "status" "OtpStatusEnum" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 3,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "verified_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "otp_verifications_pkey" PRIMARY KEY ("otp_id")
);

-- CreateIndex
CREATE INDEX "otp_verifications_phone_number_status_idx" ON "otp_verifications"("phone_number", "status");

-- CreateIndex
CREATE INDEX "otp_verifications_expires_at_idx" ON "otp_verifications"("expires_at");
