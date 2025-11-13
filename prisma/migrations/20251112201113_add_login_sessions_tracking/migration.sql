-- CreateEnum
CREATE TYPE "SessionStatusEnum" AS ENUM ('ACTIVE', 'EXPIRED', 'LOGGED_OUT', 'REVOKED');

-- CreateEnum
CREATE TYPE "LoginMethodEnum" AS ENUM ('EMAIL_PASSWORD', 'GOOGLE_OAUTH', 'PHONE_OTP', 'APPLE_ID');

-- AlterTable
ALTER TABLE "otp_verifications" ADD COLUMN     "ip_address" TEXT,
ADD COLUMN     "user_agent" TEXT;

-- CreateTable
CREATE TABLE "login_sessions" (
    "session_id" UUID NOT NULL,
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
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "login_sessions_pkey" PRIMARY KEY ("session_id")
);

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
ALTER TABLE "login_sessions" ADD CONSTRAINT "login_sessions_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("entity_id") ON DELETE RESTRICT ON UPDATE CASCADE;
