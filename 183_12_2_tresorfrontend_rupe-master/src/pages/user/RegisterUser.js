import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {postUser} from "../../comunication/FetchUser";
import ReCAPTCHA from "react-google-recaptcha";

/**
 * RegisterUser
 * @author Peter Rutschmann
 */
function RegisterUser({loginValues, setLoginValues}) {
    const navigate = useNavigate();

    const initialState = {
        firstName: "",
        lastName: "",
        email: "",
        password: "",
        passwordConfirmation: "",
        errorMessage: ""
    };
    const [credentials, setCredentials] = useState(initialState);
    const [errorMessage, setErrorMessage] = useState('');
    const [passwordErrors, setPasswordErrors] = useState([]);
    const recaptchaRef = useRef();
    const [captchaToken, setCaptchaToken] = useState(null);

    const validatePassword = (password) => {
        const errors = [];
        if (password.length < 8) {
            errors.push("Password must be at least 8 characters long.");
        }
        if (!/[A-Z]/.test(password)) {
            errors.push("Password must contain at least one uppercase letter.");
        }
        if (!/[a-z]/.test(password)) {
            errors.push("Password must contain at least one lowercase letter.");
        }
        if (!/[0-9]/.test(password)) {
            errors.push("Password must contain at least one digit.");
        }
        if (!/[^a-zA-Z0-9]/.test(password)) {
            errors.push("Password must contain at least one special character.");
        }
        return errors;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setErrorMessage('');
        setPasswordErrors([]);

        if (!captchaToken) {
            setErrorMessage("Please complete the ReCaptcha.");
            return;
        }

        //validate password strength
        const currentPasswordErrors = validatePassword(credentials.password);
        if (currentPasswordErrors.length > 0) {
            setPasswordErrors(currentPasswordErrors);
            return;
        }

        //validate
        if(credentials.password !== credentials.passwordConfirmation) {
            console.log("password != passwordConfirmation");
            setErrorMessage('Password and password-confirmation are not equal.');
            return;
        }

        try {
            await postUser({...credentials, captchaToken: captchaToken });
            setLoginValues({userName: credentials.email, password: credentials.password});
            setCredentials(initialState);
            recaptchaRef.current.reset();
            setCaptchaToken(null);
            navigate('/');
        } catch (error) {
            console.error('Failed to fetch to server:', error.message);
            setErrorMessage(error.message);
        }
    };

    return (
        <div>
            <h2>Register user</h2>
            <form onSubmit={handleSubmit}>
                <section>
                <aside>
                    <div>
                        <label>Firstname:</label>
                        <input
                            type="text"
                            value={credentials.firstName}
                            onChange={(e) =>
                                setCredentials(prevValues => ({...prevValues, firstName: e.target.value}))}
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
                                setCredentials(prevValues => ({...prevValues, lastName: e.target.value}))}
                            required
                            placeholder="Please enter your lastname *"
                        />
                    </div>
                    <div>
                        <label>Email:</label>
                        <input
                            type="text"
                            value={credentials.email}
                            onChange={(e) =>
                                setCredentials(prevValues => ({...prevValues, email: e.target.value}))}
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
                                onChange={(e) => {
                                    setCredentials(prevValues => ({...prevValues, password: e.target.value}));
                                    setPasswordErrors(validatePassword(e.target.value));
                                }}
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
                                    setCredentials(prevValues => ({...prevValues, passwordConfirmation: e.target.value}))}
                                required
                                placeholder="Please confirm your pwd *"
                            />
                        </div>
                    </aside>
                </section>
                <ReCAPTCHA
                    ref={recaptchaRef}
                    sitekey={process.env.REACT_APP_RECAPTCHA_SITE_KEY}
                    onChange={(token) => setCaptchaToken(token)}
                    onExpired={() => setCaptchaToken(null)}
                />
                <button type="submit">Register</button>
                {errorMessage && <p style={{ color: 'red' }}>{errorMessage}</p>}
                {passwordErrors.length > 0 && (
                    <div style={{ color: 'red' }}>
                        <p>Password errors:</p>
                        <ul>
                            {passwordErrors.map((error, index) => (
                                <li key={index}>{error}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </form>
        </div>
    );
}

export default RegisterUser;
