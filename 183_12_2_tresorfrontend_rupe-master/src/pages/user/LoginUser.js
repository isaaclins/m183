import { useNavigate } from 'react-router-dom';
import { useState } from 'react';

/**
 * LoginUser
 * @author Peter Rutschmann
 */
function LoginUser({loginValues, setLoginValues}) {
    const navigate = useNavigate();
    const [errorMessage, setErrorMessage] = useState('');
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log('Submitting login data:', loginValues);
        
        try {
            console.log("Password: ", loginValues.password);
            const response = await fetch('http://localhost:8080/api/users/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: loginValues.email,
                    password: loginValues.password
                })
            });
            console.log('Response status:', response.status);
            
            const data = await response.json();
            
            if (response.ok) {
                console.log('Login successful:', data);
                
                // Store user data in localStorage or sessionStorage for persistence
                localStorage.setItem('userId', data.userId);
                localStorage.setItem('userEmail', data.email);
                localStorage.setItem('isLoggedIn', 'true');
                
                // Navigate to home page or dashboard
                navigate('/');
            } else {
                console.error('Login failed:', data);
                setErrorMessage(data.message || 'Login failed. Please check your credentials.');
            }
        } catch (error) {
            console.error('Error during login:', error);
            setErrorMessage('An error occurred during login. Please try again.');
        }
    };
    
    return (
        <div>
            <h2>Login user</h2>
            {errorMessage && (
                <div className="error-message" style={{ color: 'red', marginBottom: '10px' }}>
                    {errorMessage}
                </div>
            )}
            <form onSubmit={handleSubmit}>
                <section>
                    <aside>
                        <div>
                            <label>Email:</label>
                            <input
                                type="email"
                                value={loginValues.email}
                                onChange={(e) =>
                                    setLoginValues(prevValues => ({...prevValues, email: e.target.value}))}
                                required
                                placeholder="Please enter your email *"
                            />
                        </div>
                        <div>
                            <label>Password:</label>
                            <input
                                type="password"
                                value={loginValues.password}
                                onChange={(e) =>
                                    setLoginValues(prevValues => ({...prevValues, password: e.target.value}))}
                                required
                                placeholder="Please enter your password *"
                            />
                        </div>
                    </aside>
                </section>
                <button type="submit">Login</button>
            </form>
        </div>
    );
}

export default LoginUser;