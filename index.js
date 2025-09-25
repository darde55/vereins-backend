const express = require('express');
const app = express();

const PORT = process.env.PORT || 3001;

console.log("==MINIMALTEST==: Backend wird gestartet!");

app.get('/', (req, res) => {
  res.send('Minimaltest läuft!');
});

setInterval(() => {
  console.log("==MINIMALTEST==: Backend noch aktiv.");
}, 10000);

app.listen(PORT, () => {
  console.log(`==MINIMALTEST==: Server läuft auf Port ${PORT}`);
});