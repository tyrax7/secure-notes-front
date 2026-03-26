const fs = require('fs');

function logSecurityEvent(message) {
  const timestamp = new Date().toISOString();

  const logLine = `[${timestamp}] - ${message}\n`;

  fs.appendFile('security.log', logLine, (err) => {
    if (err) {
      console.error("Erreur lors de l'écriture du log de sécurité :", err);
    }
  });
}
module.exports = logSecurityEvent;