
import { pool } from "./db.js";

async function checkUsersData() {
  try {
    const [rows] = await pool.query("SELECT * FROM users");
    console.log("Users in database:", JSON.stringify(rows, null, 2));
    
    const [roles] = await pool.query("SELECT * FROM roles");
    console.log("Roles in database:", JSON.stringify(roles, null, 2));
    
    process.exit(0);
  } catch (error) {
    console.error("Failed to check data:", error.message);
    process.exit(1);
  }
}

checkUsersData();
