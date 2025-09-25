const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const sgMail = require('@sendgrid/mail');

// Stelle sicher, dass dein SendGrid-Key gesetzt ist
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Hilfsfunktion für das Mail-Template
function getMailText(termin) {
  return `
Hallo ${termin.ansprechpartner_name || ""},

dies ist eine automatische Erinnerung zum Stichtag für den Termin:
Titel: ${termin.titel}
Datum: ${termin.datum}
Beginn: ${termin.beginn || "-"}
Ende: ${termin.ende || "-"}
Beschreibung: ${termin.beschreibung || "-"}

Bitte denke an die Organisation!

Viele Grüße
Dein Vereinsverwaltungssystem
  `.trim();
}

// Route zum manuellen Auslösen (POST /api/send-stichtag-mails)
router.post('/api/send-stichtag-mails', async (req, res) => {
  try {
    // Hole alle Termine mit Stichtag heute und noch nicht gesendeter Mail
    const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
    const result = await pool.query(
      `SELECT * FROM termine
       WHERE stichtag = $1 AND (stichtag_mail_gesendet IS NULL OR stichtag_mail_gesendet = false)
         AND ansprechpartner_mail IS NOT NULL AND ansprechpartner_mail != ''`,
      [today]
    );
    const termine = result.rows;

    let mailsSent = 0;
    for (const termin of termine) {
      try {
        await sgMail.send({
          to: termin.ansprechpartner_mail,
          from: 'tsvdienste@web.de',
          subject: `Stichtag für Termin: ${termin.titel}`,
          text: getMailText(termin)
        });
        // Nach erfolgreichem Versand das Flag setzen
        await pool.query(
          'UPDATE termine SET stichtag_mail_gesendet = true WHERE id = $1',
          [termin.id]
        );
        mailsSent++;
      } catch (mailErr) {
        console.error(`Fehler beim Mailversand an ${termin.ansprechpartner_mail}:`, mailErr);
        // Mail-Fehler, aber setze Flag NICHT!
      }
    }
    res.json({ success: true, mailsSent });
  } catch (err) {
    console.error('Fehler beim Stichtagsmail-Versand:', err);
    res.status(500).json({ error: 'Fehler beim Senden der Stichtagsmails' });
  }
});

module.exports = router;