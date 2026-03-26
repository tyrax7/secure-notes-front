const logSecurityEvent = require('../security');

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    logSecurityEvent(`Tentative d'intrusion admin par : ${req.user?.email || 'inconnu'}`);
    return res.status(403).json({ error: "Accès refusé : réservé aux administrateurs" });
};

module.exports = isAdmin;   