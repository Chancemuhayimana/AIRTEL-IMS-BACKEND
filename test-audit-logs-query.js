
import { pool } from "./db.js";

async function testAuditLogsQuery() {
  try {
    const [rows] = await pool.query(
      `
        SELECT
          a.id,
          a.actor_user_id,
          a.target_user_id,
          a.action_key,
          a.action_label,
          a.details,
          a.created_at,
          CONCAT(actor.first_name, ' ', actor.last_name) AS actor_name,
          actor.email AS actor_email,
          CONCAT(target.first_name, ' ', target.last_name) AS target_name,
          target.email AS target_email
        FROM audit_logs a
        LEFT JOIN users actor ON actor.id = a.actor_user_id
        LEFT JOIN users target ON target.id = a.target_user_id
        ORDER BY a.created_at DESC
        LIMIT 40
      `,
    );
    console.log(`Success! Found ${rows.length} audit logs.`);
    process.exit(0);
  } catch (error) {
    console.error("Query failed:", error.message);
    process.exit(1);
  }
}

testAuditLogsQuery();
