
import { pool } from "./db.js";

async function runDiagnostics() {
  const tests = [
    {
      name: "Summary Endpoint",
      queries: [
        "SELECT COUNT(*) AS totalUsers, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS activeUsers FROM users",
        "SELECT COUNT(*) AS totalRoles FROM roles",
        "SELECT COUNT(*) AS totalTables FROM information_schema.tables WHERE table_schema = DATABASE()",
        "SELECT COUNT(*) AS pendingRequests FROM requests WHERE request_status = 'pending'",
        "SELECT COUNT(*) AS unreadNotifications FROM notifications WHERE status = 'unread'"
      ]
    },
    {
      name: "Users Endpoint",
      queries: [
        `SELECT u.id, u.first_name, u.last_name, u.employee_code, u.job_title, u.employment_status, u.office_location, u.start_date, CONCAT(u.first_name, ' ', u.last_name) AS full_name, u.email, u.phone_number, u.role_id, r.name AS role_name, u.country_id, u.branch_id, u.department_id, u.unit_id, u.status, u.created_at FROM users u INNER JOIN roles r ON r.id = u.role_id ORDER BY u.created_at DESC LIMIT 100`
      ]
    },
    {
      name: "Lookups Endpoint",
      queries: [
        "SELECT id, name FROM roles",
        "SELECT id, name, iso_code FROM country",
        "SELECT id, name FROM department",
        "SELECT id, name, branch_code FROM branches",
        "SELECT id, name FROM org_units"
      ]
    },
    {
      name: "Audit Logs Endpoint",
      queries: [
        `SELECT a.id, a.actor_user_id, a.target_user_id, a.action_key, a.action_label, a.details, a.created_at, CONCAT(actor.first_name, ' ', actor.last_name) AS actor_name, actor.email AS actor_email, CONCAT(target.first_name, ' ', target.last_name) AS target_name, target.email AS target_email FROM system_logs a LEFT JOIN users actor ON actor.id = a.actor_user_id LEFT JOIN users target ON target.id = a.target_user_id ORDER BY a.created_at DESC LIMIT 40`
      ]
    },
    {
      name: "Reports Endpoint",
      queries: [
        "SELECT COUNT(*) AS totalAssets, SUM(CASE WHEN status = 'available' THEN 1 ELSE 0 END) AS availableAssets, SUM(CASE WHEN status = 'assigned' THEN 1 ELSE 0 END) AS assignedAssets, SUM(CASE WHEN status = 'maintenance' THEN 1 ELSE 0 END) AS maintenanceAssets, SUM(CASE WHEN status = 'retired' THEN 1 ELSE 0 END) AS retiredAssets, SUM(CASE WHEN status = 'lost' THEN 1 ELSE 0 END) AS lostAssets FROM equipment",
        "SELECT COUNT(*) AS totalRequests, SUM(CASE WHEN request_status = 'pending' THEN 1 ELSE 0 END) AS pendingRequests, SUM(CASE WHEN request_status = 'approved' THEN 1 ELSE 0 END) AS approvedRequests, SUM(CASE WHEN request_status = 'rejected' THEN 1 ELSE 0 END) AS rejectedRequests, SUM(CASE WHEN request_status = 'fulfilled' THEN 1 ELSE 0 END) AS fulfilledRequests FROM requests",
        "SELECT SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS activeAssignments, SUM(CASE WHEN status = 'returned' THEN 1 ELSE 0 END) AS returnedAssignments, SUM(CASE WHEN status = 'overdue' THEN 1 ELSE 0 END) AS overdueAssignments FROM assignments",
        "SELECT SUM(CASE WHEN issue_status NOT IN ('resolved', 'closed') THEN 1 ELSE 0 END) AS openIssues, SUM(CASE WHEN priority = 'high' AND issue_status NOT IN ('resolved', 'closed') THEN 1 ELSE 0 END) AS highPriorityIssues FROM issues",
        "SELECT e.id, e.asset_tag, e.equipment_name, e.status, c.name AS category_name, b.name AS branch_name FROM equipment e LEFT JOIN categories c ON c.id = e.category_id LEFT JOIN branches b ON b.id = e.branch_id ORDER BY e.created_at DESC LIMIT 10"
      ]
    },
    {
      name: "System Controls Endpoint",
      queries: [
        "SELECT setting_key, setting_value FROM system_settings",
        `SELECT b.id, b.label, b.file_name, b.snapshot_status, b.created_by_user_id, b.restored_by_user_id, b.restored_at, b.created_at, CONCAT(u.first_name, ' ', u.last_name) AS created_by_name, CONCAT(r.first_name, ' ', r.last_name) AS restored_by_name FROM backup_snapshots b LEFT JOIN users u ON u.id = b.created_by_user_id LEFT JOIN users r ON r.id = b.restored_by_user_id ORDER BY b.created_at DESC LIMIT 12`
      ]
    }
  ];

  console.log("Starting diagnostics for admin endpoints...");
  
  for (const test of tests) {
    console.log(`\nTesting ${test.name}:`);
    for (const q of test.queries) {
      try {
        await pool.query(q);
        console.log(`  [PASS] ${q.substring(0, 50)}...`);
      } catch (err) {
        console.error(`  [FAIL] ${q.substring(0, 50)}...`);
        console.error(`         Error: ${err.message}`);
      }
    }
  }

  process.exit(0);
}

runDiagnostics();
