
import { pool } from "./db.js";

async function checkData() {
  try {
    const [roles] = await pool.query("SELECT COUNT(*) as count FROM roles");
    const [countries] = await pool.query("SELECT COUNT(*) as count FROM country");
    const [departments] = await pool.query("SELECT COUNT(*) as count FROM department");
    const [branches] = await pool.query("SELECT COUNT(*) as count FROM branches");
    const [permissions] = await pool.query("SELECT COUNT(*) as count FROM permission");

    console.log("Database Data Counts:");
    console.log(`Roles: ${roles[0].count}`);
    console.log(`Countries: ${countries[0].count}`);
    console.log(`Departments: ${departments[0].count}`);
    console.log(`Branches: ${branches[0].count}`);
    console.log(`Permissions: ${permissions[0].count}`);
    
    process.exit(0);
  } catch (error) {
    console.error("Error checking database data:", error);
    process.exit(1);
  }
}

checkData();
