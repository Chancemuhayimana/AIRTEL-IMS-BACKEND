
import { pool } from "./db.js";
import crypto from "crypto";

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

async function createAdmin() {
  const email = process.env.ADMIN_EMAIL || "niyomukizatheo45@gmail.com";
  const password = process.env.ADMIN_PASSWORD || "123456789";
  
  try {
    const [roles] = await pool.query("SELECT id FROM roles WHERE name = 'admin' LIMIT 1");
    
    if (roles.length === 0) {
      console.error("Admin role not found in database.");
      process.exit(1);
    }
    
    const roleId = roles[0].id;
    const passwordHash = hashPassword(password);
    
    await pool.query(
      `INSERT INTO users (
        first_name, 
        last_name, 
        email, 
        password_hash, 
        role_id, 
        employee_code, 
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
        password_hash = VALUES(password_hash),
        role_id = VALUES(role_id),
        status = 'active'`,
      ["Theo", "Niyomukiza", email, passwordHash, roleId, "ADM-NEW", "active"]
    );
    
    console.log(`Admin user ${email} created/updated successfully.`);
    process.exit(0);
  } catch (error) {
    console.error("Error creating admin user:", error);
    process.exit(1);
  }
}

createAdmin();
