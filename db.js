import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config(); // simple, no path needed

export const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "localhost",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "root",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "airtel_global_ims",
  ssl: { rejectUnauthorized: true }, // add this for TiDB
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});