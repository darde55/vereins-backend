const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const sgMail = require('@sendgrid/mail');

// --- CONFIG LOG ---
console.log('SENDGRID_API_KEY gesetzt:', !!process.env.SENDGRID_API_KEY);
console.log('DATABASE_URL gesetzt:', !!process.env.DATABASE_URL);

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- Hilfsfunktion für das Mail-Template ---
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

// --- Route zum manuellen Auslösen (POST /api/send-stichtag-mails) ---
router.post('/api/send-stichtag-mails', async (req, res) => {
  try {
    console.log("==== Stichtagsmail-Route aufgerufen ====");
    const today = new Date().toISOString().slice(0, 10);
    console.log("Heute ist:", today);

    // --- 1. Query prüfen ---
    const result = await pool.query(
      `SELECT * FROM termine
       WHERE stichtag = $1 AND (stichtag_mail_gesendet IS NULL OR stichtag_mail_gesendet = false)
         AND ansprechpartner_mail IS NOT NULL AND ansprechpartner_mail != ''`,
      [today]
    );
    const termine = result.rows;
    console.log("Gefundene Termine für heute:", termine.length);
    if (termine.length > 0) {
      termine.forEach(t => {
        console.log("Termin:", t.id, t.titel, "| Ansprechpartner:", t.ansprechpartner_mail);
      });
    }

    let mailsSent = 0;
    for (const termin of termine) {
      try {
        console.log(`--- Versuche Mail zu senden an ${termin.ansprechpartner_mail}, Termin-ID: ${termin.id} ---`);
        if (!process.env.SENDGRID_API_KEY) {
          console.error('SENDGRID_API_KEY NICHT gesetzt!');
          continue;
        }
        // --- 2. Mail versenden ---
        await sgMail.send({
          to: termin.ansprechpartner_mail,
          from: 'tsvdienste@web.de',
          subject: `Stichtag für Termin: ${termin.titel}`,
          text: getMailText(termin)
        });
        console.log('Mail erfolgreich gesendet an', termin.ansprechpartner_mail);

        // --- 3. Update DB ---
        const updateResult = await pool.query(
          'UPDATE termine SET stichtag_mail_gesendet = true WHERE id = $1',
          [termin.id]
        );
        console.log('DB-UPDATE:', updateResult.rowCount, 'Zeile(n) aktualisiert für Termin-ID:', termin.id);
        mailsSent++;
      } catch (mailErr) {
        console.error(`Fehler beim Mailversand an ${termin.ansprechpartner_mail}:`, mailErr);
      }
    }
    console.log('==== Fertig. Gesendete Mails:', mailsSent, '====');
    res.json({ success: true, mailsSent });
  } catch (err) {
    console.error('Fehler beim Stichtagsmail-Versand:', err);
    res.status(500).json({ error: 'Fehler beim Senden der Stichtagsmails' });
  }
});

module.exports = router;