import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function AdminPanel() {
    const [users, setUsers] = useState([]);
    const navigate = useNavigate();
    const token = localStorage.getItem('token');

    useEffect(() => {
        axios.get('http://localhost:3000/api/users', {
            headers: { Authorization: `Bearer ${token}` }
        })
        .then(res => setUsers(res.data))
        .catch(() => navigate('/dashboard'));
    }, []);

    return (
        <div>
            <button onClick={() => navigate('/dashboard')}>← Retour</button>
            <h2>Utilisateurs</h2>
            {users.map(u => (
                <p key={u.id}>{u.id} — {u.email} — {u.role || 'user'}</p>
            ))}
        </div>
    );
}

export default AdminPanel;