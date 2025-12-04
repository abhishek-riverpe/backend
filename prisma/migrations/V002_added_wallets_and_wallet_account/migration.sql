-- CreateTable
CREATE TABLE "wallets" (
    "id" UUID NOT NULL,
    "entity_id" UUID NOT NULL,
    "zynk_wallet_id" TEXT NOT NULL,
    "wallet_name" TEXT NOT NULL,
    "chain" TEXT NOT NULL,
    "status" "AccountStatusEnum" NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "wallets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "wallet_accounts" (
    "id" UUID NOT NULL,
    "wallet_id" UUID NOT NULL,
    "curve" TEXT NOT NULL,
    "path_format" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "address_format" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "wallet_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "wallets_zynk_wallet_id_key" ON "wallets"("zynk_wallet_id");

-- CreateIndex
CREATE INDEX "wallets_entity_id_idx" ON "wallets"("entity_id");

-- CreateIndex
CREATE INDEX "wallets_zynk_wallet_id_idx" ON "wallets"("zynk_wallet_id");

-- CreateIndex
CREATE UNIQUE INDEX "wallet_accounts_address_key" ON "wallet_accounts"("address");

-- CreateIndex
CREATE INDEX "wallet_accounts_wallet_id_idx" ON "wallet_accounts"("wallet_id");

-- CreateIndex
CREATE INDEX "wallet_accounts_address_idx" ON "wallet_accounts"("address");

-- AddForeignKey
ALTER TABLE "wallets" ADD CONSTRAINT "wallets_entity_id_fkey" FOREIGN KEY ("entity_id") REFERENCES "entities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "wallet_accounts" ADD CONSTRAINT "wallet_accounts_wallet_id_fkey" FOREIGN KEY ("wallet_id") REFERENCES "wallets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
