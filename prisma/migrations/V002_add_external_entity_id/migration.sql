/*
  Warnings:

  - A unique constraint covering the columns `[external_entity_id]` on the table `entities` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "entities" ADD COLUMN     "external_entity_id" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "entities_external_entity_id_key" ON "entities"("external_entity_id");
