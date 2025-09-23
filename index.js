const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail'); // SendGrid importieren

const app = express();
const port = process.env.PORT || 3001;

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());

// === SENDGRID ===
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// === DATABASE ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:pekwzYpGbWUbiXFVnPmHdwuobFuWXGHR@metro.proxy.rlwy.net:56329/railway",
  ssl: { rejectUnauthorized: false }
});

// === AUTH MIDDLEWARES ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  jwt.verify(token, 'SECRET', (err, user) => {
    if (err) return res.status(403).json({ error: 'Ungültiger Token' });
    req.user = user;
    next();
  });
}

async function requireAdmin(req, res, next) {
  try {
    const result = await pool.query('SELECT role FROM users WHERE username = $1', [req.user.username]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).json({ error: 'Keine Adminrechte' });
    }
    next();
  } catch (e) {
    res.status(500).json({ error: 'Fehler bei Admin-Prüfung' });
  }
}

// === AUTH ROUTE ===
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Benutzername und Passwort nötig' });
  try {
    const result = await pool.query('SELECT username, password, role, score FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Benutzer nicht gefunden' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Falsches Passwort' });
    }
    const token = jwt.sign(
      { username: user.username, role: user.role },
      'SECRET',
      { expiresIn: '24h' }
    );
    res.json({ token, username: user.username, role: user.role, score: user.score });
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Login', detail: e.message });
  }
});

// === USER ROUTES ===
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT username, role, score FROM users');
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Laden der Nutzer' });
  }
});

// === TERMINE ROUTES ===
app.get('/api/termine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, 
        COALESCE(json_agg(te.username) FILTER (WHERE te.username IS NOT NULL), '[]') as teilnehmer
      FROM termine t
      LEFT JOIN teilnahmen te ON te.termin_id = t.id
      GROUP BY t.id
      ORDER BY t.datum ASC
    `);
    const termine = result.rows.map(t => ({
      ...t,
      teilnehmer: Array.isArray(t.teilnehmer) ? t.teilnehmer : JSON.parse(t.teilnehmer)
    }));
    res.json(termine);
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Laden der Termine' });
  }
});

// Termin erstellen (nur Admin)
app.post('/api/termine', authenticateToken, requireAdmin, async (req, res) => {
  const { titel, beschreibung, datum, beginn, ende, anzahl } = req.body;
  try {
    const result = await pool.query(`
      INSERT INTO termine (titel, beschreibung, datum, beginn, ende, anzahl)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [titel, beschreibung, datum, beginn, ende, anzahl]);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Erstellen des Termins' });
  }
});

// Termin bearbeiten (nur Admin)
app.patch('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { titel, beschreibung, datum, beginn, ende, anzahl } = req.body;
  try {
    const result = await pool.query(`
      UPDATE termine 
      SET titel = COALESCE($1, titel),
          beschreibung = COALESCE($2, beschreibung),
          datum = COALESCE($3, datum),
          beginn = COALESCE($4, beginn),
          ende = COALESCE($5, ende),
          anzahl = COALESCE($6, anzahl)
      WHERE id = $7
      RETURNING *
    `, [titel, beschreibung, datum, beginn, ende, anzahl, req.params.id]);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Bearbeiten des Termins' });
  }
});

// Termin löschen (nur Admin)
app.delete('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM termine WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Löschen des Termins' });
  }
});

// === TEILNAHME ROUTES ===

// ICS-Datei für Termin generieren (RFC 5545)
function createICS({ titel, beschreibung, datum, beginn, ende }) {
  // datum: "YYYY-MM-DD", beginn/ende: "HH:MM"
  const dtStart = beginn
    ? datum.replace(/-/g, '') + "T" + beginn.replace(":", "") + "00"
    : datum.replace(/-/g, '');
  const dtEnd = ende
    ? datum.replace(/-/g, '') + "T" + ende.replace(":", "") + "00"
    : datum.replace(/-/g, '');

  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Vereinsverwaltung//EN",
    "BEGIN:VEVENT",
    `UID:${Math.random().toString(36).substring(2)}@vereinsverwaltung.de`,
    `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, "").split(".")[0]}Z`,
    `DTSTART:${dtStart}`,
    `DTEND:${dtEnd}`,
    `SUMMARY:${titel}`,
    `DESCRIPTION:${beschreibung || ""}`,
    "END:VEVENT",
    "END:VCALENDAR"
  ].join("\r\n");
}

// Einschreiben
app.post('/api/termine/:id/teilnehmer', authenticateToken, async (req, res) => {
  const username = req.user.username;
  const termin_id = req.params.id;
  try {
    // Prüfen ob schon eingeschrieben
    const check = await pool.query(
      'SELECT * FROM teilnahmen WHERE termin_id = $1 AND username = $2',
      [termin_id, username]
    );
    if (check.rows.length !== 0) {
      return res.status(409).json({ error: 'Bereits eingeschrieben!' });
    }
    await pool.query(
      'INSERT INTO teilnahmen (termin_id, username) VALUES ($1, $2)',
      [termin_id, username]
    );

    // Hole User-Email und Termindaten
    const userResult = await pool.query('SELECT email FROM users WHERE username = $1', [username]);
    const terminResult = await pool.query('SELECT * FROM termine WHERE id = $1', [termin_id]);
    const userEmail = userResult.rows[0]?.email;
    const termin = terminResult.rows[0];

    // E-Mail mit ICS-Anhang senden
    if (userEmail && termin) {
      const icsString = createICS(termin);
      const msg = {
        to: userEmail,
        from: 'noreply@deinverein.de', // <== ERSETZEN durch verifizierte absender adresse!
        subject: 'Du bist eingeschrieben',
        text: `Du bist für den Termin "${termin.titel}" eingeschrieben!\nIm Anhang findest du die Kalenderdatei.`,
        attachments: [
          {
            content: Buffer.from(icsString).toString('base64'),
            filename: "termin.ics",
            type: "text/calendar",
            disposition: "attachment"
          }
        ]
      };
      try {
        await sgMail.send(msg);
      } catch (err) {
        console.error("SendGrid-Fehler:", err.response ? err.response.body : err);
      }
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Einschreiben' });
  }
});

// Austragen
app.delete('/api/termine/:id/teilnehmer', authenticateToken, async (req, res) => {
  const username = req.user.username;
  const termin_id = req.params.id;
  try {
    await pool.query(
      'DELETE FROM teilnahmen WHERE termin_id = $1 AND username = $2',
      [termin_id, username]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Austragen' });
  }
});

// === DEFAULT ROUTE ===
app.get('/', (req, res) => {
  res.send('Vereinsverwaltung Backend läuft!');
});

// === SERVER START ===
app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
});