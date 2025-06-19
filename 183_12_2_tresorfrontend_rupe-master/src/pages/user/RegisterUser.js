import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { postUser } from "../../comunication/FetchUser";
import HCaptcha from '@hcaptcha/react-hcaptcha';
/**
 * RegisterUser
 * @author Peter Rutschmann
 */
function RegisterUser({ loginValues, setLoginValues }) {
    const navigate = useNavigate();
    const [captchaToken, setCaptchaToken] = useState(null);

    const initialState = {
        firstName: "",
        lastName: "",
        email: "",
        password: "",
        passwordConfirmation: "",
        errorMessage: ""
    };
    const [credentials, setCredentials] = useState(initialState);
    const [errorMessages, setErrorMessages] = useState([]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setErrorMessages([]);

        // Validate passwords match
        if (credentials.password !== credentials.passwordConfirmation) {
            setErrorMessages(['Password and password-confirmation are not equal.']);
            return;
        }

        // Validate captcha
        if (!captchaToken) {
            setErrorMessages(['Please complete the CAPTCHA']);
            return;
        }

        try {
            const result = await postUser({
                ...credentials,
                captchaToken: captchaToken,
            });

            setLoginValues({ userName: credentials.email, password: credentials.password });
            setCredentials(initialState);
            navigate(`/setup-mfa?totpUri=${encodeURIComponent(result.totpUri)}`);
        } catch (error) {
            console.error('Failed to fetch to server:', error);
            
            // Handle validation errors from the backend
            if (error.response && error.response.data && error.response.data.message) {
                // Check if the error message is an array
                if (Array.isArray(error.response.data.message)) {
                    setErrorMessages(error.response.data.message);
                } else {
                    setErrorMessages([error.response.data.message]);
                }
            } else {
                setErrorMessages([error.message || 'An unknown error occurred']);
            }
        }
    };

    return (
        <div>
            <h2>Register user</h2>

            {/* Google Register Button */}
            <button
                onClick={() => window.location.href = 'http://localhost:8080/oauth2/authorization/google'}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '200px',
                    padding: '12px 20px',
                    backgroundColor: '#ffffff',
                    border: '1px solid #dadce0',
                    borderRadius: '8px',
                    fontSize: '14px',
                    fontWeight: '500',
                    color: '#3c4043',
                    cursor: 'pointer',
                    boxShadow: '0 1px 2px rgba(60, 64, 67, 0.3), 0 1px 3px rgba(60, 64, 67, 0.15)',
                    transition: 'all 0.15s ease',
                    fontFamily: 'arial, sans-serif',
                    outline: 'none'
                }}
                onMouseEnter={(e) => {
                    e.target.style.boxShadow = '0 1px 3px rgba(60, 64, 67, 0.3), 0 4px 8px rgba(60, 64, 67, 0.15)';
                    e.target.style.backgroundColor = '#f8f9fa';
                }}
                onMouseLeave={(e) => {
                    e.target.style.boxShadow = '0 1px 2px rgba(60, 64, 67, 0.3), 0 1px 3px rgba(60, 64, 67, 0.15)';
                    e.target.style.backgroundColor = '#ffffff';
                }}
                >
                {/* Google Logo SVG */}
                <svg
                    width="18"
                    height="18"
                    viewBox="0 0 24 24"
                    style={{ marginRight: '8px' }}
                >
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Sign up with Google
            </button>

            <form onSubmit={handleSubmit}>
                <section>
                    <aside>
                        <div>
                            <label>Firstname:</label>
                            <input
                                type="text"
                                value={credentials.firstName}
                                onChange={(e) =>
                                    setCredentials(prevValues => ({ ...prevValues, firstName: e.target.value }))}
                                required
                                placeholder="Please enter your firstname *"
                            />
                        </div>
                        <div>
                            <label>Lastname:</label>
                            <input
                                type="text"
                                value={credentials.lastName}
                                onChange={(e) =>
                                    setCredentials(prevValues => ({ ...prevValues, lastName: e.target.value }))}
                                required
                                placeholder="Please enter your lastname *"
                            />
                        </div>
                        <div>
                            <label>Email:</label>
                            <input
                                type="email"
                                value={credentials.email}
                                onChange={(e) =>
                                    setCredentials(prevValues => ({ ...prevValues, email: e.target.value }))}
                                required
                                placeholder="Please enter your email"
                            />
                        </div>
                    </aside>
                    <aside>
                        <div>
                            <label>Password:</label>
                            <input
                                type="password"
                                value={credentials.password}
                                onChange={(e) =>
                                    setCredentials(prevValues => ({ ...prevValues, password: e.target.value }))}
                                required
                                placeholder="Please enter your pwd *"
                            />
                        </div>
                        <div>
                            <label>Password confirmation:</label>
                            <input
                                type="password"
                                value={credentials.passwordConfirmation}
                                onChange={(e) =>
                                    setCredentials(prevValues => ({ ...prevValues, passwordConfirmation: e.target.value }))}
                                required
                                placeholder="Please confirm your pwd *"
                            />
                        </div>
                    </aside>
                </section>
                <HCaptcha
                    sitekey={process.env.REACT_APP_HCAPTCHA_SITE_KEY}
                    onVerify={setCaptchaToken}
                    onExpire={() => setCaptchaToken(null)}
                />
                <button type="submit">Register</button>
                {errorMessages.length > 0 && (
                    <div className="error-messages" style={{ color: 'red', marginTop: '1rem' }}>
                        {errorMessages.map((error, index) => (
                            <p key={index}>{error}</p>
                        ))}
                    </div>
                )}
            </form>
        </div>
    );
}

export default RegisterUser;
