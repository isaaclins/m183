import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { QRCodeCanvas } from 'qrcode.react';

function SetupMFA() {
  const navigate = useNavigate();
  const query = new URLSearchParams(useLocation().search);
  const totpUri = query.get('totpUri');

  if (!totpUri) {
    return <p>Error: TOTP setup link missing.</p>;
  }

  const secret = totpUri.split('secret=')[1].split('&')[0];

  return (
    <div>
      <h2>Multi-Factor Authentication Setup</h2>
      <p>Scan this QR code with your Authenticator app (e.g., Google Authenticator or Authy):</p>
      <QRCodeCanvas value={totpUri} size={200} />
      <p>Or enter this secret manually:</p>
      <code style={{ fontSize: '1.2rem' }}>{secret}</code>
      <br />
      <button style={{ marginTop: '2rem' }} onClick={() => navigate('/')}>
        Continue to Login
      </button>
    </div>
  );
}

export default SetupMFA;
