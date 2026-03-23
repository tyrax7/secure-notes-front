const jsonwebtoken = require('jsonwebtoken');
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Récupère le token après "Bearer"
    if (!token) {
        return res.status(401).json({ error: "Token manquant" });
    }
    try {
        const decoded = jsonwebtoken.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Erreur de vérification JWT :", err.message);
        return res.status(403).json({ error: "Token invalide" });
    }
};

module.exports = verifyToken;