const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');

const app = express();
const port = process.env.PORT || 3001;

// === UNHANDLED ERROR LOGGING ===
process.on('unhandledRejection', err => {
  console.error('[UNHANDLED REJECTION]', err);
});
process.on('uncaughtException', err => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());

// === SENDGRID ===
try {
  if (!process.env.SENDGRID_API_KEY) {
    throw new Error('SENDGRID_API_KEY nicht gesetzt!');
  }
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log("SendGrid-ApiKey geladen.");
} catch (err) {
  console.error("[SendGrid]", err);
}

// === DATABASE ===
let pool;
try {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL nicht gesetzt!');
  }
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  console.log("Postgres-DB Pool initialisiert.");
} catch (err) {
  console.error("[DB]", err);
  process.exit(1);
}

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
  const { username, password } = req.body;
  if (!username || !password) {
    console.warn("[Login] Fehlende Felder!");
    return res.status(400).json({ error: 'Benutzername und Passwort nötig' });
  }
  try {
    const result = await pool.query('SELECT username, password, role, score FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      console.warn("[Login] Benutzer nicht gefunden:", username);
      return res.status(401).json({ error: 'Benutzer nicht gefunden' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      console.warn("[Login] Falsches Passwort für:", username);
      return res.status(401).json({ error: 'Falsches Passwort' });
    }
    const token = jwt.sign(
      { username: user.username, role: user.role },
      'SECRET',
      { expiresIn: '24h' }
    );
    res.json({ token, username: user.username, role: user.role, score: user.score });
  } catch (e) {
    console.error("[Login] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Login', detail: e.message });
  }
});

// === USER ROUTES ===
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT username, role, score FROM users');
    res.json(result.rows);
  } catch (e) {
    console.error("[Users] Fehler beim Laden der Nutzer:", e);
    res.status(500).json({ error: 'Fehler beim Laden der Nutzer', detail: e.message });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password || !role) {
    console.warn("[UserAdd] Fehlende Felder!");
    return res.status(400).json({ error: 'Alle Felder erforderlich' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING username, email, role',
      [username, email, hash, role]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[UserAdd] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Anlegen des Benutzers', detail: e.message });
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
    console.error("[Termine] Fehler beim Laden der Termine:", e);
    res.status(500).json({ error: 'Fehler beim Laden der Termine', detail: e.message });
  }
});

app.post('/api/termine', authenticateToken, requireAdmin, async (req, res) => {
  const { titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score } = req.body;
  try {
    const result = await pool.query(`
      INSERT INTO termine (titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `, [titel, beschreibung, datum, beginn, ende, anzahl, stichtag, ansprechpartner_name, ansprechpartner_mail, score]);
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[TermineAdd] Fehler beim Erstellen des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Erstellen des Termins', detail: e.message });
  }
});

app.patch('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
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
    res.json(result.rows[0]);
  } catch (e) {
    console.error("[TermineEdit] Fehler beim Bearbeiten des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Bearbeiten des Termins', detail: e.message });
  }
});

app.delete('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM termine WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error("[TermineDel] Fehler beim Löschen des Termins:", e);
    res.status(500).json({ error: 'Fehler beim Löschen des Termins', detail: e.message });
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
  const username = req.body.username || req.user.username;
  const termin_id = req.params.id;
  try {
    const check = await pool.query(
      'SELECT * FROM teilnahmen WHERE termin_id = $1 AND username = $2',
      [termin_id, username]
    );
    if (check.rows.length !== 0) {
      console.warn("[Einschreiben] Bereits eingeschrieben:", username, "bei Termin", termin_id);
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
        console.log(`[Einschreiben] Mail an ${userEmail} für Termin '${termin.titel}' gesendet.`);
      } catch (err) {
        console.error("[Einschreiben] SendGrid-Fehler:", err.response ? err.response.body : err);
      }
    }

    res.json({ success: true });
  } catch (e) {
    console.error("[Einschreiben] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Einschreiben', detail: e.message });
  }
});

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
    console.error("[Austragen] Fehler:", e);
    res.status(500).json({ error: 'Fehler beim Austragen', detail: e.message });
  }
});

// === STICHTAGMAIL-ROUTE: Automatische Auffüllung + User- & Ansprechpartner-Benachrichtigung ===
app.post('/api/send-stichtag-mails', async (req, res) => {
  try {
    console.log("[Stichtag] Route aufgerufen");
    const today = new Date().toISOString().slice(0, 10);
    console.log("[Stichtag] Heute ist:", today);

    const result = await pool.query(`
      SELECT * FROM termine
      WHERE stichtag = $1 AND (stichtag_mail_gesendet IS NULL OR stichtag_mail_gesendet = false)
    `, [today]);
    const termine = result.rows;
    console.log("[Stichtag] Gefundene Termine für heute:", termine.length);

    let mailsSent = 0;
    let autoZuteilungen = 0;

    for (const termin of termine) {
      console.log("[Stichtag] Prüfe Termin:", termin.id, termin.titel);

      const teilnehmerRes = await pool.query(
        'SELECT username FROM teilnahmen WHERE termin_id = $1',
        [termin.id]
      );
      const teilnehmer = teilnehmerRes.rows.map(row => row.username);

      const freiePlaetze = Math.max(0, termin.anzahl - teilnehmer.length);
      console.log(`[Stichtag] Termin ${termin.id}: Offene Plätze: ${freiePlaetze}`);

      if (freiePlaetze > 0) {
        const freieUserRes = await pool.query(
          `SELECT * FROM users 
           WHERE username NOT IN (
              SELECT username FROM teilnahmen WHERE termin_id = $1
           )`,
          [termin.id]
        );
        const freieUser = freieUserRes.rows;
        console.log(`[Stichtag] Termin ${termin.id}: Freie User: ${freieUser.length}`);

        if (freieUser.length > 0) {
          const minScore = Math.min(...freieUser.map(u => u.score || 0));
          const kandidaten = freieUser.filter(u => (u.score || 0) === minScore);
          console.log(`[Stichtag] Termin ${termin.id}: Kandidaten mit minScore ${minScore}: ${kandidaten.map(u => u.username).join(', ')}`);

          // Shuffle
          for (let i = kandidaten.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [kandidaten[i], kandidaten[j]] = [kandidaten[j], kandidaten[i]];
          }

          const zuVergeben = Math.min(freiePlaetze, kandidaten.length);
          const ausgewaehlt = kandidaten.slice(0, zuVergeben);

          for (const user of ausgewaehlt) {
            try {
              await pool.query(
                'INSERT INTO teilnahmen (termin_id, username) VALUES ($1, $2)',
                [termin.id, user.username]
              );
              const score = termin.score || 0;
              if (score > 0) {
                await pool.query('UPDATE users SET score = COALESCE(score,0) + $1 WHERE username = $2', [score, user.username]);
              }
              if (user.email) {
                const icsString = createICS(termin);
                const msg = {
                  to: user.email,
                  from: 'tsvdienste@web.de',
                  subject: 'Du wurdest automatisch für einen Termin eingeteilt!',
                  text: `Du wurdest für den Termin "${termin.titel}" automatisch eingeteilt, weil noch Plätze frei waren.\nIm Anhang findest du die Kalenderdatei.`,
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
                  console.log(`[Stichtag] Auto-Mail an ${user.email} für Termin '${termin.titel}' gesendet.`);
                  autoZuteilungen++;
                } catch (err) {
                  console.error("[Stichtag] SendGrid-Fehler bei Auto-Mail:", err.response ? err.response.body : err);
                }
              }
            } catch (err) {
              console.error(`[Stichtag] Fehler beim Zuteilen/Benachrichtigen User ${user.username}:`, err);
            }
          }
        }
      }

      // Ansprechpartner immer benachrichtigen
      if (termin.ansprechpartner_mail) {
        try {
          const neueTeilnehmerRes = await pool.query(
            'SELECT username FROM teilnahmen WHERE termin_id = $1',
            [termin.id]
          );
          const neueTeilnehmer = neueTeilnehmerRes.rows.map(row => row.username);

          const mailText = `
Hallo ${termin.ansprechpartner_name || ""},

dies ist eine automatische Erinnerung zum Stichtag für den Termin:
Titel: ${termin.titel}
Datum: ${termin.datum}
Beginn: ${termin.beginn || "-"}
Ende: ${termin.ende || "-"}
Beschreibung: ${termin.beschreibung || "-"}

Eingeschriebene Teilnehmer: ${neueTeilnehmer.length > 0 ? neueTeilnehmer.join(', ') : 'Noch keine'}

Offene Plätze wurden (falls nötig) automatisch aufgefüllt.

Viele Grüße
Dein Vereinsverwaltungssystem
          `.trim();

          await sgMail.send({
            to: termin.ansprechpartner_mail,
            from: 'tsvdienste@web.de',
            subject: `Stichtag für Termin: ${termin.titel}`,
            text: mailText
          });
          console.log(`[Stichtag] Ansprechpartner-Mail an ${termin.ansprechpartner_mail} für Termin ${termin.id} gesendet.`);
          mailsSent++;
        } catch (mailErr) {
          console.error(`[Stichtag] Fehler beim Senden Ansprechpartner-Mail:`, mailErr);
        }
      }

      try {
        await pool.query(
          'UPDATE termine SET stichtag_mail_gesendet = true WHERE id = $1',
          [termin.id]
        );
        console.log(`[Stichtag] Termin ${termin.id} als "Mail gesendet" markiert.`);
      } catch (updateErr) {
        console.error(`[Stichtag] Fehler beim Update von stichtag_mail_gesendet für Termin ${termin.id}:`, updateErr);
      }
    }

    console.log('[Stichtag] Fertig. Ansprechpartner-Mails:', mailsSent, '| Auto-Zuteilungen:', autoZuteilungen);
    res.json({ success: true, mailsSent, autoZuteilungen });
  } catch (err) {
    console.error('[Stichtag] Fehler im Haupt-try:', err);
    res.status(500).json({ error: 'Fehler beim Senden der Stichtagsmails/Autozuteilung', detail: err.message });
  }
});

// === DEFAULT ROUTE ===
app.get('/', (req, res) => {
  res.send('Vereinsverwaltung Backend läuft!');
});

// === SERVER START ===
app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
  console.log("process.env:", JSON.stringify({
    PORT: process.env.PORT,
    SENDGRID_API_KEY: !!process.env.SENDGRID_API_KEY,
    DATABASE_URL: !!process.env.DATABASE_URL
  }));
});