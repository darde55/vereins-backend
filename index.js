require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');

const app = express();
const port = process.env.PORT || 3001;

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());

// === SENDGRID ===
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

// === DATABASE ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("railway") ? { rejectUnauthorized: false } : false
});

// === AUTH MIDDLEWARES ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  jwt.verify(token, process.env.JWT_SECRET || 'SECRET', (err, user) => {
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
      process.env.JWT_SECRET || 'SECRET',
      { expiresIn: '24h' }
    );
    res.json({ token, username: user.username, role: user.role, score: user.score });
  } catch (e) {
    res.status(500).json({ error: 'Fehler beim Login', detail: e.message });
  }
});

// === Beispielroute zum Testen ===
app.get('/api/ping', (req, res) => {
  res.json({ message: 'pong' });
});

// === DEFAULT ROUTE ===
app.get('/', (req, res) => {
  res.send('Vereinsverwaltung Backend läuft!');
});

app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
});