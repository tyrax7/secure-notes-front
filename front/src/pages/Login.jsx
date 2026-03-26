import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('http://localhost:3000/api/auth/login', { email, password });

            localStorage.setItem('user', JSON.stringify(response.data.user));
            localStorage.setItem('token', response.data.token);
            navigate('/dashboard');
        } catch (error) {
        const status = error.response?.status;
        const message = error.response?.data?.error;

        if (status === 403) {
        alert("Compte bloqué après trop de tentatives !");
        } else if (status === 401) {
        alert("Mot de passe incorrect !");
        } else {
        alert(message || "Erreur de connexion (Le back-end est-il prêt ?)");
        }
}
    };

    return (
        <div>
            <h2>Connexion</h2>
            <form onSubmit={handleLogin}>
                <input
                    type="text" placeholder="Email" value={email}
                    onChange={(e) => setEmail(e.target.value)} required
                />
                <br /><br />
                <input
                    type="password" placeholder="Mot de passe" value={password}
                    onChange={(e) => setPassword(e.target.value)} required
                />
                <br /><br />
                <button type="submit">Se connecter</button>
            </form>
        </div>
    );
}

export default Login;