
import { pool } from "./db.js";

async function testUsersQuery() {
  try {
    let query = `
      SELECT
        u.id,
        u.first_name,
        u.last_name,
        u.employee_code,
        u.job_title,
        u.employment_status,
        u.office_location,
        u.start_date,
        CONCAT(u.first_name, ' ', u.last_name) AS full_name,
        u.email,
        u.phone_number,
        u.role_id,
        r.name AS role_name,
        u.country_id,
        u.branch_id,
        u.department_id,
        u.unit_id,
        u.status,
        u.created_at
      FROM users u
      INNER JOIN roles r ON r.id = u.role_id
    `;
    query += " ORDER BY u.created_at DESC LIMIT 100";

    console.log("Testing users query...");
    const [rows] = await pool.query(query);
    console.log(`Success! Found ${rows.length} users.`);
    process.exit(0);
  } catch (error) {
    console.error("Query failed:", error.message);
    process.exit(1);
  }
}

testUsersQuery();
