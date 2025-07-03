import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

function ResetPassword() {
  const [searchParams] = useSearchParams();
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const t = searchParams.get('token');
    if (t) {
      setToken(t);
    } else {
      setError('No token provided in URL.');
    }
  }, [searchParams]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    
    try {
      const response = await fetch('http://localhost:8080/api/users/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      });
      
      if (response.ok) {
        setMessage('Your password was successfully reset.');
        setPassword('');
      } else {
        // Always try to get the server response, regardless of format
        const responseText = await response.text();
        setError(responseText || `Error ${response.status}: ${response.statusText}`);
      }
    } catch (err) {
      // Only show generic error for actual network/connection issues
      setError(`Network error: ${err.message}`);
    }
  };

  // Don't render the form if there's no token (URL error)
  if (error === 'No token provided in URL.') {
    return (
      <div>
        <h2>Set New Password</h2>
        <p style={{ color: 'red' }}>{error}</p>
      </div>
    );
  }

  return (
    <div>
      <h2>Set New Password</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <form onSubmit={handleSubmit}>
        <label>
          New Password:
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <br />
        <button type="submit">Reset Password</button>
      </form>
      {message && <p style={{ color: 'green' }}>{message}</p>}
    </div>
  );
}

export default ResetPassword;