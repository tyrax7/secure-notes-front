require('dotenv').config();
const fs = require('fs');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const { body, validationResult, ExpressValidator } = require('express-validator');
const logSecurityEvent = require('./security');

const db = require('./database');
const authMiddleware = require('./middleware/auth');

const saltRounds = 10;
const app = express();
const isAdmin = require('./middleware/isAdmin');

app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.post('/api/auth/register', [
    body('email').isEmail().withMessage("Format d'email invalide"),
    body('password').isLength({ min: 8 }).withMessage("Le mot de passe doit faire au moins 8 caractères")
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    console.log("Tentative d'inscription pour :", email);

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = `INSERT INTO users (email, password, role) VALUES (?, ?, 'user')`;
        db.run(query, [email, hashedPassword], function(err) {
            if (err) {
                console.error("Erreur base de données :", err.message);
                return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
            }
            res.status(201).json({ message: "Utilisateur créé avec succès" });
        });
    } catch (error) {
        console.error("Erreur lors du hachage :", error);
        res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
    }
});

app.post('/api/auth/login', limiter, (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) {
            console.error("Erreur DB login :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
        if (!user) return res.status(401).json({ error: "Identifiants incorrects" });

        const now = Date.now();
        if (user.lock_until && now < user.lock_until) {
            const remainingMin = Math.ceil((user.lock_until - now) / 60000);
            return res.status(423).json({
                error: `Compte verrouillé. Réessayez dans ${remainingMin} minute(s).`
            });
        }

        try {
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                const newAttempts = (user.failed_attempts || 0) + 1;
                if (newAttempts >= 3) {
                    const lockUntil = Date.now() + 15 * 60 * 1000;
                    db.run(
                        `UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?`,
                        [newAttempts, lockUntil, user.id]
                    );
                    logSecurityEvent(`Compte verrouillé après ${newAttempts} tentatives : ${email}`);
                    return res.status(423).json({ error: "Trop de tentatives. Compte verrouillé pour 15 minutes." });
                }

                db.run(
                    `UPDATE users SET failed_attempts = ? WHERE id = ?`,
                    [newAttempts, user.id]
                );
                return res.status(401).json({
                    error: "Identifiants incorrects",
                    attempts_left: 3 - newAttempts
                });
            }

            db.run(
                `UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?`,
                [user.id]
            );
            logSecurityEvent(`Connexion réussie pour : ${email}`);

            const payload = { id: user.id, email: user.email, role: user.role };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
            delete user.password;
            res.json({ user, token });

        } catch (error) {
            console.error("Erreur :", error);
            res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
    });
});

app.get("/api/notes", authMiddleware, (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const query = isAdmin ? "SELECT * FROM notes" : "SELECT * FROM notes WHERE user_id = ?";
    const params = isAdmin ? [] : [req.user.id];

    db.all(query, params, (err, notes) => {
        if (err) {
            console.error("Erreur DB notes :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
        res.json(notes);
    });
});

app.get('/api/users', authMiddleware, isAdmin, (req, res) => {
    const query = "SELECT id, email, role FROM users";
    db.all(query, [], (err, users) => {
        if (err) {
            console.error("Erreur DB users :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
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
    db.run(query, [content, userId], function(err) {
        if (err) {
            console.error("Erreur DB ajout note :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
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
        if (err) {
            console.error("Erreur DB suppression :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "Note introuvable ou accès refusé" });
        }
        res.json({ message: "Note supprimée avec succès" });
    });
});
app.delete("/api/users/me", authMiddleware, (req, res) => {
    const userId = req.user.id;

    db.run(`DELETE FROM notes WHERE user_id = ?`, [userId], function(err) {
        if (err) {
            console.error("Erreur suppression notes :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }

        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err) {
                console.error("Erreur suppression utilisateur :", err.message);
                return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
            }

            res.clearCookie('jwt');
            res.json({ message: "Compte et données supprimés avec succès." });
        });
    });
});

/*Mission 1 : L'Édition de Profil*/
app.put('/api/users/:id', authMiddleware, [
    body('email').optional().isEmail().withMessage("Format d'email invalide"),
], async (req, res) => {
    const IdFromUrl = req.params.id;
    const authenticatedUserId = req.user.id;
    if (parseInt(IdFromUrl) !== authenticatedUserId) {
        return res.status(403).json({ error: "Accès refusé : vous ne pouvez modifier que votre propre profil" });
    }

    // Validation express-validator
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, bio } = req.body;

    const updates = [];
    const params = [];

    if (email) {
        updates.push("email = ?");
        params.push(email);
    }

    if (bio !== undefined) {
        const cleanBio = sanitizeHtml(bio, {
            allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
            allowedAttributes: {},
        });
        updates.push("bio = ?");
        params.push(cleanBio);
    }

    if (updates.length === 0) {
        return res.status(400).json({ error: "Aucune donnée à mettre à jour." });
    }

    params.push(IdFromUrl);
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = ?`;

    db.run(query, params, function (err) {
        if (err) {
            console.error("Erreur DB update profil :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "Utilisateur introuvable." });
        }
        res.json({ message: "Profil mis à jour avec succès." });
    });
}); 
/*Mission 2 : Le Verrouillage du Back-Office*/
app.get('/api/admin/users', authMiddleware, isAdmin, (req, res) => {
    db.all(`SELECT id, email, role,bio FROM users`, [], (err, users) => {
        if (err) {
            console.error("Erreur DB users :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }
        res.json(users);
    });
});
/*Mission 3 : La Modération Extrême*/
const AdminDeleteLimiter=  rateLimit({windowMs:  15* 60 *1000, max : 3, message : "Trop de tentatives de suppression. Veuillez réessayer plus tard."});
app.delete('/api/admin/users/:id',authMiddleware,isAdmin,AdminDeleteLimiter,(req,res)=>{
    const userId = req.params.id;
     db.run(`DELETE FROM notes WHERE user_id = ?`, [userId], function(err) {
        if (err) {
            console.error("Erreur suppression notes :", err.message);
            return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
        }

        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err) {
                console.error("Erreur suppression utilisateur :", err.message);
                return res.status(500).json({ error: "Une erreur interne du serveur est survenue." });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: "Utilisateur introuvable." });
            }
            if (this.changes > 0) { 
                fs.appendFile('admin_actions.log', `[${new Date().toISOString()}] - L'admin ${req.user.id} a supprimé l'utilisateur ${userId}\n`, (err) => {
                    if (err) {
                        console.error("Erreur écriture log :", err.message);
                    }
                });
                res.json({ message: "Utilisateur supprimé avec succès." });
            }
        });
    });
});
/* Mission 5 : L'Audit en temps réel */
app.get('/api/admin/logs', authMiddleware, isAdmin, (req, res) => {
    const logFilePath = './admin_actions.log';
    if (!fs.existsSync(logFilePath)) {
        return res.json({ logs: [] });
    }
    fs.readFile(logFilePath, 'utf8', (err, data) => {
        if (err) {
            console.error("Erreur lors de la lecture des logs :", err.message);
            return res.status(500).json({ error: "Erreur interne lors de la récupération des journaux." });
        }
        const logsArray = data.trim().split('\n').filter(line => line.length > 0);

        res.json({ logs: logsArray });
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});