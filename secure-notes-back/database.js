const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./securenotes.db');
db.serialize(() => {
db.run(`CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT UNIQUE,
password TEXT,
role TEXT

)`);
db.run(`CREATE TABLE IF NOT EXISTS notes (
id INTEGER PRIMARY KEY AUTOINCREMENT,
title TEXT,
content TEXT,
user_id INTEGER,
FOREIGN KEY (user_id) REFERENCES users(id)
)`);
db.run(`DELETE FROM notes WHERE id = 1`);
db.run(`INSERT INTO notes (title, content, user_id) VALUES ('Ma première note', 'Voici le texte de ma note.', 1)`);
console.log("Base de données SQLite initialisée avec succès.");
});
module.exports = db;