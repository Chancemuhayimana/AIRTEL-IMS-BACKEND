import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import mysql from "mysql2/promise";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const schemaPath = path.resolve(__dirname, "../database/schema.sql");

async function setupDatabase() {
  const schemaSql = await fs.readFile(schemaPath, "utf8");

  const connection = await mysql.createConnection({
    host: process.env.MYSQL_HOST || "localhost",
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || "root",
    password: process.env.MYSQL_PASSWORD || "",
    multipleStatements: true,
  });

  try {
    await connection.query(schemaSql);
    console.log("Database schema created successfully in XAMPP MySQL.");
  } finally {
    await connection.end();
  }
}

setupDatabase().catch((error) => {
  console.error("Failed to set up database:", error.message);
  process.exit(1);
});
