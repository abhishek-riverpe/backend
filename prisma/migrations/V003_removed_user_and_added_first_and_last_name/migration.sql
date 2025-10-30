/*
  Warnings:

  - You are about to drop the column `name` on the `entities` table. All the data in the column will be lost.
  - You are about to drop the `User` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `first_name` to the `entities` table without a default value. This is not possible if the table is not empty.
  - Added the required column `last_name` to the `entities` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "entities" DROP COLUMN "name",
ADD COLUMN     "first_name" TEXT NOT NULL,
ADD COLUMN     "last_name" TEXT NOT NULL;

-- DropTable
DROP TABLE "User";
