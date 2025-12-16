/*
  Warnings:

  - You are about to drop the column `encrypted_data` on the `entities` table. All the data in the column will be lost.
  - You are about to drop the column `encryption_key_id` on the `entities` table. All the data in the column will be lost.
  - You are about to drop the column `locked_until` on the `entities` table. All the data in the column will be lost.
  - You are about to drop the column `login_attempts` on the `entities` table. All the data in the column will be lost.
  - You are about to drop the column `password` on the `entities` table. All the data in the column will be lost.
  - The `status` column on the `entities` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - You are about to drop the `kyc_documents` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `login_sessions` table. If the table is not empty, all the data it contains will be lost.
  - A unique constraint covering the columns `[auth0_sub]` on the table `entities` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `auth0_sub` to the `entities` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "UserStatusEnum" AS ENUM ('REGISTERED', 'PENDING', 'ACTIVE', 'SUSPENDED', 'CLOSED');

-- DropForeignKey
ALTER TABLE "kyc_documents" DROP CONSTRAINT "kyc_documents_kyc_session_id_fkey";

-- DropForeignKey
ALTER TABLE "login_sessions" DROP CONSTRAINT "login_sessions_entity_id_fkey";

-- AlterTable
ALTER TABLE "entities" DROP COLUMN "encrypted_data",
DROP COLUMN "encryption_key_id",
DROP COLUMN "locked_until",
DROP COLUMN "login_attempts",
DROP COLUMN "password",
ADD COLUMN     "auth0_sub" TEXT NOT NULL,
ALTER COLUMN "first_name" DROP NOT NULL,
ALTER COLUMN "last_name" DROP NOT NULL,
ALTER COLUMN "email_verified" DROP DEFAULT,
DROP COLUMN "status",
ADD COLUMN     "status" "UserStatusEnum" NOT NULL DEFAULT 'REGISTERED';

-- DropTable
DROP TABLE "kyc_documents";

-- DropTable
DROP TABLE "login_sessions";

-- DropEnum
DROP TYPE "EntityStatusEnum";

-- DropEnum
DROP TYPE "LoginMethodEnum";

-- DropEnum
DROP TYPE "SessionStatusEnum";

-- CreateTable
CREATE TABLE "external_accounts" (
    "id" UUID NOT NULL,
    "zynk_external_account_id" TEXT NOT NULL,
    "entity_id" UUID NOT NULL,
    "wallet_account_id" UUID NOT NULL,
    "wallet_address" TEXT NOT NULL,
    "jurisdiction_id" TEXT NOT NULL,
    "status" "AccountStatusEnum" NOT NULL DEFAULT 'INACTIVE',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "external_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "external_accounts_zynk_external_account_id_key" ON "external_accounts"("zynk_external_account_id");

-- CreateIndex
CREATE UNIQUE INDEX "entities_auth0_sub_key" ON "entities"("auth0_sub");

-- AddForeignKey
ALTER TABLE "external_accounts" ADD CONSTRAINT "external_accounts_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "external_accounts" ADD CONSTRAINT "external_accounts_wallet_account_id_fkey" FOREIGN KEY ("wallet_account_id") REFERENCES "wallet_accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
