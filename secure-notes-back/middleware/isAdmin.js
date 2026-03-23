const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: "Accès refusé : réservé aux administrateurs" });
};

module.exports = isAdmin;