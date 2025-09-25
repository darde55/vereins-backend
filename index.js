console.log("==== Vereinsverwaltung Backend: Starte Initialisierung ====");

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');

console.log("Alle Module geladen.");

const app = express();
const port = process.env.PORT || 3001;

console.log("Express App initialisiert. PORT:", port);

// === MIDDLEWARE ===
app.use(cors());
console.log("CORS Middleware aktiviert.");
app.use(express.json());
console.log("express.json Middleware aktiviert.");

// === SENDGRID ===
if (!process.env.SENDGRID_API_KEY) {
  console.error("FEHLER: SENDGRID_API_KEY nicht gesetzt!");
} else {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log("SendGrid API-Key gesetzt.");
}

// === DATABASE ===
console.log("Initialisiere Datenbankpool ...");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:pekwzYpGbWUbiXFVnPmHdwuobFuWXGHR@metro.proxy.rlwy.net:56329/railway",
  ssl: { rejectUnauthorized: false }
});
console.log("Postgres Pool erstellt.");

// Teste Datenbankverbindung sofort beim Start
pool.connect()
  .then(client => {
    console.log("Verbindung zur Postgres-Datenbank erfolgreich.");
    client.release();
  })
  .catch(err => {
    console.error("FEHLER beim Verbinden zur Postgres-Datenbank:", err);
  });

// === AUTH MIDDLEWARES ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.warn("[Auth] Kein Token im Header!");
    return res.status(401).json({ error: 'Kein Token' });
  }
  jwt.verify(token, 'SECRET', (err, user) => {
    if (err) {
      console.warn("[Auth] Ungültiger Token!");
      return res.status(403).json({ error: 'Ungültiger Token' });
    }
    req.user = user;
    next();
  });
}

async function requireAdmin(req, res, next) {
  try {
    const result = await pool.query('SELECT role FROM users WHERE username = $1', [req.user.username]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      console.warn("[Admin] Keine Adminrechte für User:", req.user.username);
      return res.status(403).json({ error: 'Keine Adminrechte' });
    }
    next();
  } catch (e) {
    console.error("[Admin] Fehler bei Admin-Prüfung:", e);
    res.status(500).json({ error: 'Fehler bei Admin-Prüfung', detail: e.message });
  }
}

// === AUTH ROUTE ===
app.post('/api/login', async (req, res) => {
  console.log("[/api/login] Aufruf erhalten für Benutzer:", req.body.username);
  const { username, password } = req.body;
  if (!username || !password) {
    console.warn("[/api/login] Fehlende Felder!");
    return res.status(400).json({ error: 'Benutzername und Passwort nötig' });
  }
  try {
    const result = await pool.query('SELECT username, password, role, score FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      console.warn("[/api/login] Benutzer nicht gefunden:", username);
      return res.status(401).json({ error: 'Benutzer nicht gefunden' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      console.warn("[/api/login] Falsches Passwort für:", username);
      return res.status(401).json({ error: 'Falsches Passwort' });
    }
    const token = jwt.sign(
      { username: user.username, role: user.role },
      'SECRET',
      { expiresIn: '24h' }
    );
    console.log("[/api/login] Login erfolgreich für:", username);
    res.json({ token, username: user.username, role: user.role, score: user.score });
  } catch (e) {
    console.error("[/api/login] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Login', detail: e.message });
  }
});

// === USER ROUTES ===
app.get('/api/users', authenticateToken, async (req, res) => {
  console.log("[/api/users] GET aufgerufen von", req.user?.username);
  try {
    const result = await pool.query('SELECT username, role, score FROM users');
    res.json(result.rows);
  } catch (e) {
    console.error("[/api/users] Fehler beim Laden der Nutzer:", e);
    res.status(500).json({ error: 'Fehler beim Laden der Nutzer' });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  console.log("[/api/users] POST (neuer User) aufgerufen von", req.user?.username);
  const { username, email, password, role } = req.body;
  if (!username || !email || !password || !role) {
    console.warn("[/api/users] Fehlende Felder!");
    return res.status(400).json({ error: 'Alle Felder erforderlich' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING username, email, role',
      [username, email, hash, role]
    );
    console.log("[/api/users] Neuer User angelegt:", username);
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[/api/users] Fehler beim Anlegen des Benutzers:", e);
    res.status(500).json({ error: 'Fehler beim Anlegen des Benutzers', detail: e.message });
  }
});

// === TERMINE ROUTES ===
app.get('/api/termine', authenticateToken, async (req, res) => {
  console.log("[/api/termine] GET aufgerufen von", req.user?.username);
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
    console.error("[/api/termine] Fehler beim Laden der Termine:", e);
    res.status(500).json({ error: 'Fehler beim Laden der Termine' });
  }
});

app.post('/api/termine', authenticateToken, requireAdmin, async (req, res) => {
  console.log("[/api/termine] POST (neuer Termin) aufgerufen von", req.user?.username);
  const { titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score } = req.body;
  try {
    const result = await pool.query(`
      INSERT INTO termine (titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `, [titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score]);
    console.log("[/api/termine] Termin angelegt:", titel, "am", datum);
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[/api/termine] Fehler beim Erstellen des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Erstellen des Termins' });
  }
});

app.patch('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  console.log("[/api/termine/:id] PATCH aufgerufen von", req.user?.username, "Termin-ID:", req.params.id);
  const { titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score } = req.body;
  try {
    const result = await pool.query(`
      UPDATE termine 
      SET titel = COALESCE($1, titel),
          beschreibung = COALESCE($2, beschreibung),
          datum = COALESCE($3, datum),
          beginn = COALESCE($4, beginn),
          ende = COALESCE($5, ende),
          anzahl = COALESCE($6, anzahl),
          stichtag = COALESCE($7, stichtag),
          ansprechpartner_name = COALESCE($8, ansprechpartner_name),
          ansprechpartner_mail = COALESCE($9, ansprechpartner_mail),
          score = COALESCE($10, score)
      WHERE id = $11
      RETURNING *
    `, [titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score, req.params.id]);
    console.log("[/api/termine/:id] Termin bearbeitet:", req.params.id);
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[/api/termine/:id] Fehler beim Bearbeiten des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Bearbeiten des Termins' });
  }
});

app.delete('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  console.log("[/api/termine/:id] DELETE aufgerufen von", req.user?.username, "Termin-ID:", req.params.id);
  try {
    await pool.query('DELETE FROM termine WHERE id = $1', [req.params.id]);
    console.log("[/api/termine/:id] Termin gelöscht:", req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error("[/api/termine/:id] Fehler beim Löschen des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Löschen des Termins' });
  }
});

// === TEILNAHME ROUTES ===
function createICS({ titel, beschreibung, datum, beginn, ende }) {
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

app.post('/api/termine/:id/teilnehmer', authenticateToken, async (req, res) => {
  console.log("[/api/termine/:id/teilnehmer] POST aufgerufen von", req.user?.username, "Termin-ID:", req.params.id);
  const username = req.body.username || req.user.username;
  const termin_id = req.params.id;
  try {
    const check = await pool.query(
      'SELECT * FROM teilnahmen WHERE termin_id = $1 AND username = $2',
      [termin_id, username]
    );
    if (check.rows.length !== 0) {
      console.warn("[/api/termine/:id/teilnehmer] User ist schon eingeschrieben:", username);
      return res.status(409).json({ error: 'Bereits eingeschrieben!' });
    }
    await pool.query(
      'INSERT INTO teilnahmen (termin_id, username) VALUES ($1, $2)',
      [termin_id, username]
    );
    const terminResult = await pool.query('SELECT score FROM termine WHERE id = $1', [termin_id]);
    const score = terminResult.rows[0]?.score || 0;
    if (score > 0) {
      await pool.query('UPDATE users SET score = COALESCE(score,0) + $1 WHERE username = $2', [score, username]);
    }
    const userResult = await pool.query('SELECT email FROM users WHERE username = $1', [username]);
    const terminAllResult = await pool.query('SELECT * FROM termine WHERE id = $1', [termin_id]);
    const userEmail = userResult.rows[0]?.email;
    const termin = terminAllResult.rows[0];
    if (userEmail && termin) {
      const icsString = createICS(termin);
      const msg = {
        to: userEmail,
        from: 'tsvdienste@web.de',
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
        console.log("[/api/termine/:id/teilnehmer] Einschreibe-Mail an", userEmail, "gesendet.");
      } catch (err) {
        console.error("[/api/termine/:id/teilnehmer] SendGrid-Fehler:", err.response ? err.response.body : err);
      }
    }
    res.json({ success: true });
  } catch (e) {
    console.error("[/api/termine/:id/teilnehmer] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Einschreiben' });
  }
});

app.delete('/api/termine/:id/teilnehmer', authenticateToken, async (req, res) => {
  console.log("[/api/termine/:id/teilnehmer] DELETE aufgerufen von", req.user?.username, "Termin-ID:", req.params.id);
  const username = req.user.username;
  const termin_id = req.params.id;
  try {
    await pool.query(
      'DELETE FROM teilnahmen WHERE termin_id = $1 AND username = $2',
      [termin_id, username]
    );
    res.json({ success: true });
  } catch (e) {
    console.error("[/api/termine/:id/teilnehmer] Fehler beim Austragen:", e);
    res.status(500).json({ error: 'Fehler beim Austragen' });
  }
});

// === STICHTAGMAIL-ROUTE ===
app.post('/api/send-stichtag-mails', async (req, res) => {
  console.log("[/api/send-stichtag-mails] Route aufgerufen.");
  try {
    const today = new Date().toISOString().slice(0, 10);
    const result = await pool.query(`
      SELECT * FROM termine
      WHERE stichtag = $1 AND (stichtag_mail_gesendet IS NULL OR stichtag_mail_gesendet = false)
        AND ansprechpartner_mail IS NOT NULL AND ansprechpartner_mail != ''
    `, [today]);
    const termine = result.rows;
    console.log("[/api/send-stichtag-mails] Gefundene Termine für heute:", termine.length);

    let mailsSent = 0;
    for (const termin of termine) {
      try {
        const teilnehmerRes = await pool.query(
          'SELECT username FROM teilnahmen WHERE termin_id = $1',
          [termin.id]
        );
        const teilnehmer = teilnehmerRes.rows.map(row => row.username);

        const mailText = `
Hallo ${termin.ansprechpartner_name || ""},

dies ist eine automatische Erinnerung zum Stichtag für den Termin:
Titel: ${termin.titel}
Datum: ${termin.datum}
Beginn: ${termin.beginn || "-"}
Ende: ${termin.ende || "-"}
Beschreibung: ${termin.beschreibung || "-"}

Eingeschriebene Teilnehmer: ${teilnehmer.length > 0 ? teilnehmer.join(', ') : 'Noch keine'}

Bitte denke an die Organisation!

Viele Grüße
Dein Vereinsverwaltungssystem
        `.trim();

        console.log("[/api/send-stichtag-mails] Versuche Mail zu senden an", termin.ansprechpartner_mail, "Termin-ID:", termin.id);
        if (!process.env.SENDGRID_API_KEY) {
          console.error('SENDGRID_API_KEY NICHT gesetzt!');
          continue;
        }
        await sgMail.send({
          to: termin.ansprechpartner_mail,
          from: 'tsvdienste@web.de',
          subject: `Stichtag für Termin: ${termin.titel}`,
          text: mailText
        });
        console.log("[/api/send-stichtag-mails] Stichtagsmail erfolgreich an", termin.ansprechpartner_mail, "versendet (Termin:", termin.titel, "ID:", termin.id, ")");
        const updateResult = await pool.query(
          'UPDATE termine SET stichtag_mail_gesendet = true WHERE id = $1',
          [termin.id]
        );
        console.log("[/api/send-stichtag-mails] DB-UPDATE:", updateResult.rowCount, "Zeile(n) aktualisiert für Termin-ID:", termin.id);
        mailsSent++;
      } catch (mailErr) {
        console.error("[/api/send-stichtag-mails] Fehler beim Mailversand an", termin.ansprechpartner_mail, ":", mailErr);
      }
    }
    console.log("[/api/send-stichtag-mails] Fertig. Gesendete Mails:", mailsSent);
    res.json({ success: true, mailsSent });
  } catch (err) {
    console.error("[/api/send-stichtag-mails] Fehler beim Stichtagsmail-Versand:", err);
    res.status(500).json({ error: 'Fehler beim Senden der Stichtagsmails' });
  }
});

// === DEFAULT ROUTE ===
app.get('/', (req, res) => {
  console.log("[/] GET Root-Route wurde aufgerufen.");
  res.send('Vereinsverwaltung Backend läuft!');
});

// === SERVER START ===
app.listen(port, () => {
  console.log(`==== Vereinsverwaltung Backend läuft auf Port ${port} ====`);
});