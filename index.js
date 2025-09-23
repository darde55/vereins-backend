// Fehler-Logger ganz oben!
process.on('uncaughtException', err => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', err => console.error('Unhandled Rejection:', err));

// Workaround: Prozess wach halten (Railway)
setInterval(() => {}, 10000);

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createEvent } = require('ics');

// === SENDGRID-Integration ===
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const app = express();
const port = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'dein_geheimes_jwt_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://vereins-frontend.vercel.app';

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.use(express.json());

// PostgreSQL-Pool einrichten
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Tabellen initialisieren
async function initTables() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS termine (
      id SERIAL PRIMARY KEY,
      titel TEXT NOT NULL,
      datum TEXT NOT NULL,
      beschreibung TEXT,
      anzahl INTEGER NOT NULL,
      stichtag TEXT,
      ansprechpartner_name TEXT,
      ansprechpartner_mail TEXT,
      score INTEGER DEFAULT 0
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
      email TEXT,
      active BOOLEAN NOT NULL DEFAULT true,
      score INTEGER DEFAULT 0
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS teilnahmen (
      id SERIAL PRIMARY KEY,
      termin_id INTEGER NOT NULL REFERENCES termine(id) ON DELETE CASCADE,
      username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      UNIQUE(termin_id, username)
    )`);
    console.log('Postgres Tabellen initialisiert!');
  } catch (e) {
    console.error("Tabellen-Initialisierung fehlgeschlagen:", e);
  }
}
initTables();

// Healthcheck-Route für Datenbankverbindung
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ db: 'ok' });
  } catch (err) {
    res.status(500).json({ db: 'error', details: err.message });
  }
});

// Auth Middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token fehlt" });
  }
  const token = auth.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token ungültig" });
    req.user = user;
    next();
  });
}
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: "Nur für Admins erlaubt" });
  }
  next();
}

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'User nicht gefunden' });
    if (!user.active) return res.status(403).json({ error: 'User ist gesperrt' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Falsches Passwort' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET,
      { expiresIn: '2h' }
    );
    res.json({ token, username: user.username, role: user.role });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Alle User anzeigen (Admin)
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, email, role, active, score FROM users');
    res.json(result.rows);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Einzelnen User anzeigen (Admin oder User selbst)
app.get('/api/users/:id', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  if (req.user.role !== "admin" && req.user.id !== id) {
    return res.status(403).json({ error: "Keine Berechtigung" });
  }
  try {
    const result = await pool.query('SELECT id, username, email, role, active, score FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User nicht gefunden" });
    res.json(user);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// User anlegen (Admin)
app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const { username, password, role, email } = req.body;
  if (!username || !password || !role || !email) return res.status(400).json({ error: 'Alle Felder erforderlich' });
  const hashedPw = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password, role, email) VALUES ($1, $2, $3, $4) RETURNING id, username, role, email, score',
      [username, hashedPw, role, email]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if ((err.message && err.message.toLowerCase().includes('unique')) || (err.code === '23505')) {
      return res.status(400).json({ error: 'Username existiert bereits' });
    }
    return res.status(500).json({ error: err.message });
  }
});

// User bearbeiten (Admin oder User selbst) - Username-Änderung möglich!
app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  const { username, email, role, password, active, score } = req.body;
  if (req.user.role !== "admin" && req.user.id !== id) {
    return res.status(403).json({ error: "Keine Berechtigung" });
  }
  let fields = [];
  let params = [];
  let paramIdx = 1;
  let alterUsername = null;
  if (username && req.user.role === "admin") {
    // Hole alten Username
    const result = await pool.query('SELECT username FROM users WHERE id = $1', [id]);
    alterUsername = result.rows[0]?.username;
    if (alterUsername && alterUsername !== username) {
      fields.push(`username = $${paramIdx++}`);
      params.push(username);
    }
  }
  if (email) { fields.push(`email = $${paramIdx++}`); params.push(email); }
  if (password) {
    const hashedPw = await bcrypt.hash(password, 10);
    fields.push(`password = $${paramIdx++}`); params.push(hashedPw);
  }
  if (role && req.user.role === "admin") { fields.push(`role = $${paramIdx++}`); params.push(role); }
  if (typeof active !== 'undefined' && req.user.role === "admin") { fields.push(`active = $${paramIdx++}`); params.push(active ? true : false); }
  if (typeof score !== 'undefined' && req.user.role === "admin") { fields.push(`score = $${paramIdx++}`); params.push(Number(score)); }
  if (fields.length === 0) return res.status(400).json({ error: "Keine Felder zu ändern übergeben" });
  params.push(id);
  try {
    await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${paramIdx}`, params);
    // Username-Referenzen in teilnahmen anpassen
    if (alterUsername && username && alterUsername !== username) {
      await pool.query('UPDATE teilnahmen SET username = $1 WHERE username = $2', [username, alterUsername]);
    }
    res.json({ erfolg: true });
  } catch (err) {
    if ((err.code === '23505') || (err.message && err.message.toLowerCase().includes('unique'))) {
      return res.status(400).json({ error: 'Username existiert bereits' });
    }
    return res.status(500).json({ error: err.message });
  }
});

// User löschen (nur Admin)
app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  try {
    // Username herausfinden für teilnahmen-Löschung
    const result = await pool.query('SELECT username FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User nicht gefunden" });
    await pool.query('DELETE FROM teilnahmen WHERE username = $1', [user.username]);
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ erfolg: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Termine abrufen (mit Teilnehmern)
app.get('/api/termine', async (req, res) => {
  try {
    const termineResult = await pool.query('SELECT * FROM termine');
    const teilnahmenResult = await pool.query('SELECT * FROM teilnahmen');
    const result = termineResult.rows.map(t => ({
      ...t,
      teilnehmer: teilnahmenResult.rows.filter(te => te.termin_id === t.id).map(te => te.username)
    }));
    res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Neuen Termin anlegen (nur Admin)
app.post('/api/termine', authMiddleware, adminOnly, async (req, res) => {
  const { titel, datum, beschreibung, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score } = req.body;
  if (!titel || !datum || !anzahl) {
    return res.status(400).json({ error: 'Titel, Datum und Anzahl erforderlich' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO termine (titel, datum, beschreibung, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [
        titel,
        datum,
        beschreibung,
        anzahl,
        stichtag || null,
        ansprechpartner_name || null,
        ansprechpartner_mail || null,
        typeof score !== 'undefined' ? Number(score) : 0
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Termin bearbeiten (nur Admin)
app.put('/api/termine/:id', authMiddleware, adminOnly, async (req, res) => {
  const termin_id = Number(req.params.id);
  const { titel, datum, beschreibung, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score } = req.body;
  try {
    await pool.query(
      `UPDATE termine SET titel = $1, datum = $2, beschreibung = $3, anzahl = $4,
         stichtag = $5, ansprechpartner_name = $6, ansprechpartner_mail = $7, score = $8 WHERE id = $9`,
      [
        titel,
        datum,
        beschreibung,
        anzahl,
        stichtag || null,
        ansprechpartner_name || null,
        ansprechpartner_mail || null,
        typeof score !== 'undefined' ? Number(score) : 0,
        termin_id
      ]
    );
    res.json({ erfolg: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Termin löschen (nur Admin)
app.delete('/api/termine/:id', authMiddleware, adminOnly, async (req, res) => {
  const termin_id = Number(req.params.id);
  try {
    await pool.query('DELETE FROM teilnahmen WHERE termin_id = $1', [termin_id]);
    await pool.query('DELETE FROM termine WHERE id = $1', [termin_id]);
    res.json({ erfolg: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Einschreiben für einen Termin mit E-Mail und ICS (über SendGrid)
app.post('/api/termine/:id/einschreiben', authMiddleware, async (req, res) => {
  const termin_id = Number(req.params.id);
  const username = req.user.username;
  try {
    const terminResult = await pool.query('SELECT * FROM termine WHERE id = $1', [termin_id]);
    const termin = terminResult.rows[0];
    if (!termin) return res.status(404).json({ error: 'Termin nicht gefunden' });

    const teilnahmenResult = await pool.query('SELECT username FROM teilnahmen WHERE termin_id = $1', [termin_id]);
    const teilnahmen = teilnahmenResult.rows;
    if (teilnahmen.some(te => te.username === username)) {
      return res.status(400).json({ error: 'Schon eingeschrieben' });
    }
    if (teilnahmen.length >= termin.anzahl) {
      return res.status(400).json({ error: 'Keine Plätze mehr frei' });
    }
    const userResult = await pool.query('SELECT email, score FROM users WHERE username = $1', [username]);
    const userRow = userResult.rows[0];
    if (!userRow || !userRow.email) {
      return res.status(400).json({ error: 'Keine E-Mail für diesen Nutzer hinterlegt' });
    }
    await pool.query('INSERT INTO teilnahmen (termin_id, username) VALUES ($1, $2)', [termin_id, username]);

    // Score an User vergeben
    if (typeof termin.score === "number" && termin.score > 0) {
      await pool.query(
        'UPDATE users SET score = COALESCE(score,0) + $1 WHERE username = $2',
        [termin.score, username]
      );
    }

    const dateObj = new Date(termin.datum);
    const event = {
      start: [
        dateObj.getFullYear(),
        dateObj.getMonth() + 1,
        dateObj.getDate(),
        dateObj.getHours(),
        dateObj.getMinutes(),
      ],
      duration: { hours: 1 },
      title: termin.titel,
      description: termin.beschreibung,
      location: termin.ort || "",
      organizer: {
        name: termin.ansprechpartner_name || "VereinsApp",
        email: termin.ansprechpartner_mail || process.env.MAIL_FROM
      }
    };
    createEvent(event, async (icsError, icsValue) => {
      if (icsError) {
        return res.json({ erfolg: true, warnung: "Einschreibung ok, aber keine Kalenderdatei" });
      }
      try {
        await sgMail.send({
          to: userRow.email,
          from: process.env.MAIL_FROM, // Deine bestätigte SendGrid-Absenderadresse!
          subject: `Bestätigung: "${termin.titel}"`,
          text: `Du bist zum Termin "${termin.titel}" am ${dateObj.toLocaleString("de-DE")} angemeldet.`,
          attachments: [
            {
              filename: 'termin.ics',
              content: Buffer.from(icsValue).toString('base64'),
              type: 'text/calendar',
              disposition: 'attachment',
              content_id: 'terminics'
            }
          ]
        });
        res.json({ erfolg: true });
      } catch (mailErr) {
        console.error("Fehler beim Mailversand (SendGrid):", mailErr?.response?.body || mailErr);
        res.json({ erfolg: true, warnung: "Einschreibung ok, aber Mailversand fehlgeschlagen." });
      }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Test-Route (Healthcheck für Railway)
app.get('/api', (req, res) => {
  res.send('API läuft!');
});

// Root-Route für Healthcheck
app.get('/', (req, res) => {
  res.send('Backend läuft!');
});

// Server starten (immer mit richtigem Port!)
app.listen(port, () => {
  console.log(`Backend läuft auf Port ${port}`);
});