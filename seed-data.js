
import { pool } from "./db.js";

const airtelCountries = [
  { name: "Chad", isoCode: "TD", currencyCode: "XAF" },
  { name: "Congo", isoCode: "CG", currencyCode: "XAF" },
  { name: "Democratic Republic of the Congo", isoCode: "CD", currencyCode: "CDF" },
  { name: "Gabon", isoCode: "GA", currencyCode: "XAF" },
  { name: "Kenya", isoCode: "KE", currencyCode: "KES" },
  { name: "Madagascar", isoCode: "MG", currencyCode: "MGA" },
  { name: "Malawi", isoCode: "MW", currencyCode: "MWK" },
  { name: "Niger", isoCode: "NE", currencyCode: "XOF" },
  { name: "Nigeria", isoCode: "NG", currencyCode: "NGN" },
  { name: "Rwanda", isoCode: "RW", currencyCode: "RWF" },
  { name: "Seychelles", isoCode: "SC", currencyCode: "SCR" },
  { name: "Tanzania", isoCode: "TZ", currencyCode: "TZS" },
  { name: "Uganda", isoCode: "UG", currencyCode: "UGX" },
  { name: "Zambia", isoCode: "ZM", currencyCode: "ZMW" },
];

const departments = ["IT", "HR", "Finance", "Operations", "Sales", "Marketing"];
const orgUnits = ["Business Unit", "Support Unit", "Technical Unit", "Sales Unit"];
const permissions = [
  { code: "user.create", name: "Create User", module: "User Management" },
  { code: "user.view", name: "View User", module: "User Management" },
  { code: "user.edit", name: "Edit User", module: "User Management" },
  { code: "inventory.view", name: "View Inventory", module: "Inventory" },
  { code: "inventory.manage", name: "Manage Inventory", module: "Inventory" },
  { code: "request.create", name: "Create Request", module: "Requests" },
  { code: "request.approve", name: "Approve Request", module: "Requests" },
];

async function seed() {
  try {
    console.log("Starting data seeding...");

    // 1. Seed Countries
    for (const c of airtelCountries) {
      await pool.query(
        "INSERT INTO country (name, iso_code, currency_code) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name)",
        [c.name, c.isoCode, c.currencyCode]
      );
    }
    console.log("Countries seeded.");

    // Get country IDs
    const [countryRows] = await pool.query("SELECT id, name FROM country");
    
    // 2. Seed Branches and Departments
    for (const country of countryRows) {
      const branchName = `${country.name} HQ`;
      const branchCode = `${country.name.substring(0, 3).toUpperCase()}-HQ`;
      
      const [branchResult] = await pool.query(
        "INSERT INTO branches (country_id, name, branch_code) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name)",
        [country.id, branchName, branchCode]
      );
      
      const branchId = branchResult.insertId || (await pool.query("SELECT id FROM branches WHERE branch_code = ?", [branchCode]))[0][0].id;

      for (const deptName of departments) {
        await pool.query(
          "INSERT INTO department (country_id, branch_id, name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name)",
          [country.id, branchId, deptName]
        );
      }
    }
    console.log("Branches and Departments seeded.");

    // 3. Seed Org Units
    for (const unitName of orgUnits) {
      await pool.query(
        "INSERT INTO org_units (name) VALUES (?) ON DUPLICATE KEY UPDATE name=VALUES(name)",
        [unitName]
      );
    }
    console.log("Org Units seeded.");

    // 4. Seed Permissions
    for (const p of permissions) {
      await pool.query(
        "INSERT INTO permission (code, name, module_name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name)",
        [p.code, p.name, p.module]
      );
    }
    console.log("Permissions seeded.");

    console.log("Seeding completed successfully.");
    process.exit(0);
  } catch (error) {
    console.error("Seeding failed:", error);
    process.exit(1);
  }
}

seed();
