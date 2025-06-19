import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

const OAuth2RedirectHandler = ({ setLoginValues }) => {
    const navigate = useNavigate();
    const ranOnce = useRef(false);

    useEffect(() => {
        if (ranOnce.current) return;
        ranOnce.current = true;

        const params = new URLSearchParams(window.location.search);
        const token = params.get('token');
        const email = params.get('email');
        const userId = params.get('userId');
        const password = params.get('password'); // Not for prod, but ok for dev


        if (token && email && userId && password) {
            localStorage.setItem('token', token);
            localStorage.setItem('userEmail', email);
            localStorage.setItem('userId', userId);
            localStorage.setItem('isLoggedIn', 'true');
            localStorage.setItem('password', password);

            // Set login values for parent state
            if (setLoginValues) {
                setLoginValues({ email, password });
            }

            navigate('/');
        } else {
            console.error('OAuth2 callback missing required parameters');
            navigate('/user/login');
        }
    }, [navigate, setLoginValues]);

    return <p>Redirecting...</p>;
};

export default OAuth2RedirectHandler;
