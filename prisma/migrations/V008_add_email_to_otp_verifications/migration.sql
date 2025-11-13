-- AlterTable
ALTER TABLE "otp_verifications" 
ALTER COLUMN "phone_number" DROP NOT NULL,
ALTER COLUMN "country_code" DROP NOT NULL,
ADD COLUMN "email" TEXT;

-- CreateIndex
CREATE INDEX "otp_verifications_email_status_idx" ON "otp_verifications"("email", "status");

