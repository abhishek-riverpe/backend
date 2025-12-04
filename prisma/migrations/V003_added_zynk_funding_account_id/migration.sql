/*
  Warnings:

  - A unique constraint covering the columns `[zynk_funding_account_id]` on the table `funding_accounts` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "funding_accounts" ADD COLUMN     "zynk_funding_account_id" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "funding_accounts_zynk_funding_account_id_key" ON "funding_accounts"("zynk_funding_account_id");
