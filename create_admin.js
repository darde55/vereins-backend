const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./termine.db');
const username = 'admin';
const password = 'adminpass';
const role = 'admin';

bcrypt.hash(password, 10).then(hashedPw => {
  db.run(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
    [username, hashedPw, role],
    function (err) {
      if (err) {
        console.error(err.message);
      } else {
        console.log('Admin-User angelegt!');
      }
      db.close();
    }
  );
});