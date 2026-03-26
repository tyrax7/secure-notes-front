const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./securenotes.db');

async function initDb() {
    const hash = await bcrypt.hash('monMotDePasse', 10);
    const mdp = await bcrypt.hash('userpass', 10);
    const user    = await bcrypt.hash('user',10)
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

    db.run(`DELETE FROM notes`);
    db.run(`DELETE FROM users`);

    db.run(
      `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
      ['admin@example.com', hash, 'admin'] 
    );
    db.run(
      `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
      ['user@example.com', mdp, 'admin'] 
    );
    db.run(
      `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
      ['lucas@example.com', user, 'user'] 
    );
    
    db.run(
      `INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)`,
      ['Ma première note', 'Voici le texte de ma note.', 1]
    );

    console.log("Base de données SQLite initialisée avec succès.");
  });
}

initDb();

module.exports = db;