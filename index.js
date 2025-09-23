const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcrypt'); // Wichtig: bcrypt installieren!

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: "postgresql://postgres:pekwzYpGbWUbiXFVnPmHdwuobFuWXGHR@metro.proxy.rlwy.net:56329/railway",
  ssl: { rejectUnauthorized: false }
});

// JWT-Auth Middleware
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
async function requireAdmin(req, res, next) {
  try {
    const result = await pool.query('SELECT role FROM users WHERE username = $1', [req.user.username]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin')
      return res.sendStatus(403);
    next();
  } catch {
    res.sendStatus(500);
  }
}

// LOGIN gegen die Datenbank (mit bcrypt!)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT username, password, role, score FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Login fehlgeschlagen' });
    const user = result.rows[0];
    // Vergleiche das eingegebene Passwort mit dem Hash aus der DB
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Login fehlgeschlagen' });
    const token = jwt.sign({ username: user.username }, 'SECRET');
    res.json({ token, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Login' });
  }
});

// Nutzer-Liste
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT username, score, role FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Abrufen der Nutzer' });
  }
});

// Termine inkl. Teilnehmer
app.get('/api/termine', authenticateToken, async (req, res) => {
  try {
    const termineResult = await pool.query('SELECT * FROM termine');
    const termine = termineResult.rows;

    for (let t of termine) {
      const teilnehmerRes = await pool.query(
        'SELECT username FROM teilnehmer WHERE termin_id = $1',
        [t.id]
      );
      t.teilnehmer = teilnehmerRes.rows.map(r => r.username);
    }
    res.json(termine);
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Abrufen der Termine' });
  }
});

// Teilnehmer HINZUFÜGEN (nur Admin)
app.post('/api/termine/:id/teilnehmer', authenticateToken, requireAdmin, async (req, res) => {
  const terminId = req.params.id;
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username erforderlich' });
  try {
    // Existiert der Termin?
    const termin = await pool.query('SELECT * FROM termine WHERE id = $1', [terminId]);
    if (termin.rows.length === 0)
      return res.status(404).json({ error: 'Termin nicht gefunden' });

    // Existiert der User?
    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (user.rows.length === 0)
      return res.status(404).json({ error: 'User nicht gefunden' });

    // Schon Teilnehmer?
    const teilnehmerResult = await pool.query(
      'SELECT * FROM teilnehmer WHERE termin_id = $1 AND username = $2', [terminId, username]
    );
    if (teilnehmerResult.rows.length === 0) {
      await pool.query(
        'INSERT INTO teilnehmer (termin_id, username) VALUES ($1, $2)', [terminId, username]
      );
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Hinzufügen des Teilnehmers' });
  }
});

// Teilnehmer ENTFERNEN (nur Admin)
app.delete('/api/termine/:id/teilnehmer/:username', authenticateToken, requireAdmin, async (req, res) => {
  const terminId = req.params.id;
  const username = req.params.username;
  try {
    await pool.query(
      'DELETE FROM teilnehmer WHERE termin_id = $1 AND username = $2',
      [terminId, username]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Entfernen des Teilnehmers' });
  }
});

// Termin ANZAHL BEARBEITEN (nur Admin)
app.patch('/api/termine/:id', authenticateToken, requireAdmin, async (req, res) => {
  const terminId = req.params.id;
  const { anzahl } = req.body;
  if (typeof anzahl !== 'number' || anzahl <= 0)
    return res.status(400).json({ error: 'Ungültige Anzahl' });
  try {
    await pool.query(
      'UPDATE termine SET anzahl = $1 WHERE id = $2',
      [anzahl, terminId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Fehler beim Aktualisieren der Anzahl' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('Server läuft auf Port', PORT));