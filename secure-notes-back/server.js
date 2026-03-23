require('dotenv').config();
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');

const db = require('./database');
const authMiddleware = require('./middleware/auth');

const saltRounds = 10;
const app = express();
const isAdmin = require('./middleware/isAdmin');


app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    console.log("Tentative d'inscription pour :", email);

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = `INSERT INTO users (email, password, role) VALUES (?, ?, 'user')`;
        db.run(query, [email, hashedPassword], function(err) {
            if (err) {
                console.error("Erreur base de données :", err.message);
                return res.status(500).json({ error: "Erreur lors de l'inscription" });
            }
            res.status(201).json({ message: "Utilisateur créé avec succès" });
        });
    } catch (error) {
        console.error("Erreur lors du hachage :", error);
        res.status(500).json({ error: "Erreur serveur lors de la création du compte" });
    }
});

app.post('/api/auth/login', limiter, (req, res) => {
    const { email, password } = req.body;
    const query = `SELECT * FROM users WHERE email = ?`;

    db.get(query, [email], async (err, user) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        if (!user) return res.status(401).json({ error: "Identifiants incorrects" });

        try {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const payload = { id: user.id, email: user.email, role: user.role };
                const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
                delete user.password;
                res.json({ user, token });
            } else {
                res.status(401).json({ error: "Identifiants incorrects" });
            }
        } catch (error) {
            console.error("Erreur lors de la comparaison :", error);
            res.status(500).json({ error: "Erreur serveur" });
        }
    });
});

app.get("/api/notes", authMiddleware, (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const query = isAdmin ? "SELECT * FROM notes" : "SELECT * FROM notes WHERE user_id = ?";
    const params = isAdmin ? [] : [req.user.id];

    db.all(query, params, (err, notes) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        res.json(notes);
    });
});

app.get('/api/users', authMiddleware, isAdmin, (req, res) => {
    const query = "SELECT id, email, role FROM users";
    db.all(query, [], (err, users) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        res.json(users);
    });
});

app.post("/api/notes", authMiddleware, (req, res) => {
  const { content } = req.body;
  const userId = req.user.id;

  if (!content) {
    return res.status(400).json({ error: "Le contenu de la note est obligatoire" });
  }
  const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

  db.run(query, [content, userId], function (err) {
    if (err) {
      console.error("Erreur lors de l'ajout de la note :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.status(201).json({
      message: "Note ajoutée avec succès",
      note: {
        id: this.lastID,
        content: content,
        user_id: userId
      }
    });
  });
});

app.delete("/api/notes/:id", authMiddleware, (req, res) => {
    const noteId = req.params.id;
    const userId = req.user.id;
    const query = "DELETE FROM notes WHERE id = ? AND user_id = ?";
    db.run(query, [noteId, userId], function(err) {
        if (err) return res.status(500).json({ error: "Erreur serveur" });

        if (this.changes === 0) {
            return res.status(404).json({ error: "Note introuvable ou accès refusé" });
        }

        res.json({ message: "Note supprimée avec succès" });
    });
});
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});