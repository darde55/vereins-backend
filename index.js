const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { createEvent } = require('ics');

const app = express();
const port = process.env.PORT || 3001;
const SECRET = 'dein_geheimes_jwt_secret';

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://vereins-frontend.vercel.app'; // <-- Anpassen!

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true // falls du Authentifizierung oder Cookies nutzt
}));
app.use(express.json());

// DB anlegen/öffnen & Tabellen
const db = new sqlite3.Database('./termine.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS termine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titel TEXT NOT NULL,
    datum TEXT NOT NULL,
    beschreibung TEXT,
    anzahl INTEGER NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    email TEXT,
    active INTEGER NOT NULL DEFAULT 1
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS teilnahmen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    termin_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    UNIQUE(termin_id, username)
  )`);
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
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(400).json({ error: 'User nicht gefunden' });
    if (user.active !== 1) return res.status(403).json({ error: 'User ist gesperrt' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Falsches Passwort' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET,
      { expiresIn: '2h' }
    );
    res.json({ token, username: user.username, role: user.role });
  });
});

// Alle User anzeigen (Admin)
app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  db.all('SELECT id, username, email, role, active FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// User suchen/filtern (Admin)
app.get('/api/users/search', authMiddleware, adminOnly, (req, res) => {
  const { username, email, role } = req.query;
  let sql = 'SELECT id, username, email, role, active FROM users WHERE 1=1';
  let params = [];
  if (username) {
    sql += ' AND username LIKE ?';
    params.push('%' + username + '%');
  }
  if (email) {
    sql += ' AND email LIKE ?';
    params.push('%' + email + '%');
  }
  if (role) {
    sql += ' AND role = ?';
    params.push(role);
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Einzelnen User anzeigen (Admin oder User selbst)
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  if (req.user.role !== "admin" && req.user.id !== id) {
    return res.status(403).json({ error: "Keine Berechtigung" });
  }
  db.get('SELECT id, username, email, role, active FROM users WHERE id = ?', [id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: "User nicht gefunden" });
    res.json(user);
  });
});

// User anlegen (Admin)
app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const { username, password, role, email } = req.body;
  if (!username || !password || !role || !email) return res.status(400).json({ error: 'Alle Felder erforderlich' });
  const hashedPw = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
    [username, hashedPw, role, email],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'Username existiert bereits' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, username, role, email });
    }
  );
});

// User bearbeiten (Admin oder User selbst)
app.put('/api/users/:id', authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  const { email, role, password, active } = req.body;
  if (req.user.role !== "admin" && req.user.id !== id) {
    return res.status(403).json({ error: "Keine Berechtigung" });
  }
  // Nur Admin darf Rolle und Aktiv-Status ändern
  let fields = [];
  let params = [];
  if (email) { fields.push('email = ?'); params.push(email); }
  if (password) {
    const hashedPw = await bcrypt.hash(password, 10);
    fields.push('password = ?'); params.push(hashedPw);
  }
  if (role && req.user.role === "admin") { fields.push('role = ?'); params.push(role); }
  if (typeof active !== 'undefined' && req.user.role === "admin") { fields.push('active = ?'); params.push(active ? 1 : 0); }
  if (fields.length === 0) return res.status(400).json({ error: "Keine Felder zu ändern übergeben" });
  params.push(id);
  db.run(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, params, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ erfolg: true });
  });
});

// User löschen (nur Admin)
app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ erfolg: true });
  });
});

// Termine abrufen (mit Teilnehmern)
app.get('/api/termine', (req, res) => {
  db.all('SELECT * FROM termine', [], (err, termineRows) => {
    if (err) return res.status(500).json({error: err.message});
    db.all('SELECT * FROM teilnahmen', [], (err2, teilnahmenRows) => {
      if (err2) return res.status(500).json({error: err2.message});
      const result = termineRows.map(t => ({
        ...t,
        teilnehmer: teilnahmenRows.filter(te => te.termin_id === t.id).map(te => te.username)
      }));
      res.json(result);
    });
  });
});

// Neuen Termin anlegen (nur Admin)
app.post('/api/termine', authMiddleware, adminOnly, (req, res) => {
  const { titel, datum, beschreibung, anzahl } = req.body;
  if (!titel || !datum || !anzahl) {
    return res.status(400).json({ error: 'Titel, Datum und Anzahl erforderlich' });
  }
  db.run(
    'INSERT INTO termine (titel, datum, beschreibung, anzahl) VALUES (?, ?, ?, ?)',
    [titel, datum, beschreibung, anzahl],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({ id: this.lastID, titel, datum, beschreibung, anzahl });
    }
  );
});

// Termin bearbeiten (nur Admin)
app.put('/api/termine/:id', authMiddleware, adminOnly, (req, res) => {
  const termin_id = Number(req.params.id);
  const { titel, datum, beschreibung, anzahl } = req.body;
  db.run(
    'UPDATE termine SET titel = ?, datum = ?, beschreibung = ?, anzahl = ? WHERE id = ?',
    [titel, datum, beschreibung, anzahl, termin_id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ erfolg: true });
    }
  );
});

// Termin löschen (nur Admin)
app.delete('/api/termine/:id', authMiddleware, adminOnly, (req, res) => {
  const termin_id = Number(req.params.id);
  db.run('DELETE FROM termine WHERE id = ?', [termin_id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run('DELETE FROM teilnahmen WHERE termin_id = ?', [termin_id]);
    res.json({ erfolg: true });
  });
});

// Einschreiben für einen Termin mit E-Mail und ICS
const transporter = nodemailer.createTransport({
  host: "smtp.web.de",
  port: 587,
  secure: false,
  auth: {
    user: "tsvdienste@web.de",
    pass: "TSV_Dienste123",
  },
});

app.post('/api/termine/:id/einschreiben', authMiddleware, (req, res) => {
  const termin_id = Number(req.params.id);
  const username = req.user.username;
  db.get('SELECT * FROM termine WHERE id = ?', [termin_id], (err, termin) => {
    if (err || !termin) return res.status(404).json({ error: 'Termin nicht gefunden' });
    db.all('SELECT username FROM teilnahmen WHERE termin_id = ?', [termin_id], (err2, teilnahmen) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (teilnahmen.some(te => te.username === username)) {
        return res.status(400).json({ error: 'Schon eingeschrieben' });
      }
      if (teilnahmen.length >= termin.anzahl) {
        return res.status(400).json({ error: 'Keine Plätze mehr frei' });
      }
      db.get('SELECT email FROM users WHERE username = ?', [username], (errUser, userRow) => {
        if (errUser || !userRow || !userRow.email) {
          return res.status(400).json({ error: 'Keine E-Mail für diesen Nutzer hinterlegt' });
        }
        db.run('INSERT INTO teilnahmen (termin_id, username) VALUES (?, ?)', [termin_id, username], (err3) => {
          if (err3) return res.status(400).json({ error: 'Fehler beim Einschreiben' });
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
            organizer: { name: "VereinsApp", email: "noreply@deinserver.de" },
          };
          createEvent(event, async (icsError, icsValue) => {
            if (icsError) {
              return res.json({ erfolg: true, warnung: "Einschreibung ok, aber keine Kalenderdatei" });
            }
            try {
              await transporter.sendMail({
                from: 'tsvdienste@web.de',
                to: userRow.email,
                subject: `Bestätigung: "${termin.titel}"`,
                text: `Du bist zum Termin "${termin.titel}" am ${dateObj.toLocaleString("de-DE")} angemeldet.`,
                icalEvent: {
                  filename: 'termin.ics',
                  method: 'REQUEST',
                  content: icsValue,
                }
              });
              res.json({ erfolg: true });
            } catch (mailErr) {
              res.json({ erfolg: true, warnung: "Einschreibung ok, aber Mailversand fehlgeschlagen." });
            }
          });
        });
      });
    });
  });
});

// Test-Route (optional, um zu prüfen, ob das Backend läuft)
app.get('/api', (req, res) => {
  res.send('API läuft!');
});

// Server starten
app.listen(port, () => {
  console.log(`Backend läuft auf Port ${port}`);
});