const Database = require('better-sqlite3');
const db = new Database('/var/lib/sentinel-agent/sentinel.db');
try {
    const stmt = db.prepare("SELECT * FROM blocks");
    const rows = stmt.all();
    console.log("Blocks table exists. Rows:", rows.length);
    console.log(rows);
} catch (e) {
    console.error("Error querying blocks table:", e.message);
}
