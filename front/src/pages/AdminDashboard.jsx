import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function AdminDashboard() {
    const [users, setUsers] = useState([]);
    const navigate = useNavigate();
    const token = localStorage.getItem('token');  
    const [logs, setLogs] = useState([]);  
    useEffect(() => {
        const user = JSON.parse(localStorage.getItem('user'));
        if (!user || user.role !== 'admin') {
            navigate('/dashboard');
        }
        
        axios.get('http://localhost:3000/api/admin/users', {
            headers: { Authorization: `Bearer ${token}` }
        })
        .then(res => setUsers(res.data))
        .catch(() => navigate('/dashboard'))

    }, []);
    const fetchLogs = () => {
        axios.get('http://localhost:3000/api/admin/logs', {
            headers: { Authorization: `Bearer ${token}` }
        })
        .then(res => setLogs(res.data.logs))
        .catch(err => console.error("Erreur logs:", err));
    };
const handleBan = (id) => {
    axios.delete(`http://localhost:3000/api/admin/users/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
    }).then(() => {
        setUsers(users.filter(u => u.id !== id));
        fetchLogs();
    })
    .catch(err => console.error("Erreur ban:", err));
};

    return (
        <div>
            <button onClick={() => navigate('/dashboard')}>← Retour</button>
            <h2>Utilisateurs</h2>
            {users.map(u => (
                <p key={u.id}>
                    {u.id} — {u.email} — {u.role || 'user'}
                    <button onClick={() => handleBan(u.id)}>Bannir</button>
                </p>
            ))}
            <h2>Logs</h2>
            <ul>
                {logs.length > 0 ? (
                    logs.map((log, index) => (
                        <li key={index}>{log}</li>
                    ))
                ) : (
                    <li>Aucun log disponible</li>
                )}
            </ul>
        </div>
    );
}

export default AdminDashboard;

  