const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

app.use(cors());
app.use(express.json());

// Beispiel: Datenhaltung im Speicher (ersetze durch DB in Produktion)
let users = [
  // Beispieluser
  { username: 'admin', password: 'admin', role: 'admin', score: 100 },
  { username: 'max', password: 'max', role: 'user', score: 50 },
];
let termine = [
  // Beispieltermin
  {
    id: '1',
    titel: 'Schiedsrichter',
    datum: '2025-09-26',
    beginn: '10:00',
    ende: '12:00',
    beschreibung: 'Schiedsrichtertermin',
    anzahl: 2,
    teilnehmer: ['max'],
    score: 5,
    ansprechpartner_name: 'Max Mustermann',
    ansprechpartner_mail: 'max@example.com'
  }
];

// Hilfsfunktion: Authentifizierung & Admin-Check
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, 'SECRET', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}
function requireAdmin(req, res, next) {
  const user = users.find(u => u.username === req.user.username);
  if (!user || user.role !== 'admin') return res.sendStatus(403);
  next();
}

// --- API-Routen ---

// Alle Termine abrufen
app.get('/api/termine', authenticateToken, (req, res) => {
  res.json(termine);
});

// Termin-Teilnehmer HINZUFÜGEN (nur Admin)
app.post('/api/termine/:id/teilnehmer', authenticateToken, requireAdmin, (req, res) => {
  const termin = termine.find(t => t.id === req.params.id);
  if (!termin) return res.status(404).json({ error: 'Termin nicht gefunden' });
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username erforderlich' });
  if (!users.find(u => u.username === username)) return res.status(404).json({ error: 'User nicht gefunden' });
  if (!termin.teilnehmer.includes(username)) {
    termin.teilnehmer.push(username);
  }
  res.json({ success: true, termin });
});

// Termin-Teilnehmer ENTFERNEN (nur Admin)
app.delete('/api/termine/:id/teilnehmer/:username', authenticateToken, requireAdmin, (req, res) => {
  const termin = termine.find(t => t.id === req.params.id);
  if (!termin) return res.status(404).json({ error: 'Termin nicht gefunden' });
  termin.teilnehmer = termin.teilnehmer.filter(u => u !== req.params.username);
  res.json({ success: true, termin });
});

// Termin-ANZAHL BEARBEITEN (nur Admin)
app.patch('/api/termine/:id', authenticateToken, requireAdmin, (req, res) => {
  const termin = termine.find(t => t.id === req.params.id);
  if (!termin) return res.status(404).json({ error: 'Termin nicht gefunden' });
  if (typeof req.body.anzahl === 'number' && req.body.anzahl > 0) {
    termin.anzahl = req.body.anzahl;
    res.json({ success: true, termin });
  } else {
    res.status(400).json({ error: 'Ungültige Anzahl' });
  }
});

// Nutzer abrufen (für Score, Rollen etc.)
app.get('/api/users', authenticateToken, (req, res) => {
  res.json(users.map(u => ({
    username: u.username,
    score: u.score,
    role: u.role
  })));
});

// Beispiel-Login (nur zu Demo-Zwecken!)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Login fehlgeschlagen' });
  const token = jwt.sign({ username: user.username }, 'SECRET');
  res.json({ token, username: user.username, role: user.role });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('Server läuft auf Port', PORT));