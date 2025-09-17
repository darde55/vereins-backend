const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./termine.db');
db.run('ALTER TABLE users ADD COLUMN email TEXT', (err) => {
  if (err) {
    console.error("Fehler oder Spalte existiert schon:", err.message);
  } else {
    console.log("E-Mail-Spalte hinzugefügt!");
  }
  db.close();
});