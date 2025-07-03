import '../../App.css';
import React, { useEffect, useState } from 'react';
import { getSecretsforUser } from "../../comunication/FetchSecrets";

/**
 * Secrets
 * @author Peter Rutschmann
 */
const Secrets = ({ loginValues }) => {
    const [secrets, setSecrets] = useState([]);
    const [errorMessage, setErrorMessage] = useState('');
    const [selectedSecret, setSelectedSecret] = useState(null);

    useEffect(() => {
        const fetchSecrets = async () => {
            setErrorMessage('');
            if (!loginValues.email) {
                console.error('Secrets: No valid email, please do login first:' + loginValues);
                setErrorMessage("No valid email, please do login first.");
            } else {
                try {
                    const data = await getSecretsforUser(loginValues);
                    setSecrets(data);
                } catch (error) {
                    console.error('Failed to fetch to server:', error.message);
                    setErrorMessage(error.message);
                }
            }
        };
        fetchSecrets();
    }, [loginValues]);

    // Function to parse JSON content safely
    const parseContent = (contentString) => {
        try {
            return JSON.parse(contentString);
        } catch (e) {
            return contentString;
        }
    };

    // Function to render content based on secret type
    const renderSecretDetails = (secret) => {
        const parsedContent = parseContent(secret.content);
        const content = parsedContent.content || {};
        
        switch (content.kind) {
            case 'credential':
                return (
                    <div className="secret-detail">
                        <h3>{parsedContent.title || 'Credential'}</h3>
                        <div className="secret-info">
                            <p><strong>Username:</strong> {content.userName}</p>
                            <p><strong>Password:</strong> {content.password}</p>
                            <p><strong>URL:</strong> {content.url}</p>
                        </div>
                    </div>
                );
            case 'creditcard':
                return (
                    <div className="secret-detail">
                        <h3>{content.cardtype || 'Credit Card'}</h3>
                        <div className="secret-info">
                            <p><strong>Card Number:</strong> {content.cardnumber}</p>
                            <p><strong>Expiration:</strong> {content.expiration}</p>
                            <p><strong>CVV:</strong> {content.cvv}</p>
                        </div>
                    </div>
                );
            case 'note':
                return (
                    <div className="secret-detail">
                        <h3>{content.title || 'Note'}</h3>
                        <div className="secret-info">
                            <p><strong>Content:</strong> {content.content}</p>
                        </div>
                    </div>
                );
            default:
                return (
                    <div className="secret-detail">
                        <h3>Unknown Secret Type</h3>
                        <pre>{JSON.stringify(content, null, 2)}</pre>
                    </div>
                );
        }
    };

    // Get icon for secret type
    const getSecretIcon = (secretType) => {
        switch (secretType) {
            case 'credential':
                return '🔑';
            case 'creditcard':
                return '💳';
            case 'note':
                return '📝';
            default:
                return '🔒';
        }
    };

    // Get the type of secret from content
    const getSecretType = (contentString) => {
        try {
            const parsedContent = JSON.parse(contentString);
            return parsedContent.content?.kind || 'unknown';
        } catch (e) {
            return 'unknown';
        }
    };

    // Get the title of the secret
    const getSecretTitle = (contentString) => {
        try {
            const parsedContent = JSON.parse(contentString);
            return parsedContent.title || parsedContent.content?.title || 'Untitled';
        } catch (e) {
            return 'Untitled';
        }
    };

    return (
        <div className="secrets-container">
            <h1>My Secrets Vault</h1>
            {errorMessage && <p className="error-message">{errorMessage}</p>}

            <div className="secrets-layout">
                <div className="secrets-list">
                    <h2>My Secrets</h2>
                    {secrets?.length > 0 ? (
                        <ul>
                            {secrets.map(secret => {
                                const secretType = getSecretType(secret.content);
                                const title = getSecretTitle(secret.content);
                                
                                return (
                                    <li 
                                        key={secret.id} 
                                        className={`secret-item ${selectedSecret === secret.id ? 'selected' : ''}`}
                                        onClick={() => setSelectedSecret(secret.id === selectedSecret ? null : secret.id)}
                                    >
                                        <span className="secret-icon">{getSecretIcon(secretType)}</span>
                                        <span className="secret-title">{title}</span>
                                        <span className="secret-type">{secretType}</span>
                                    </li>
                                );
                            })}
                        </ul>
                    ) : (
                        <p className="no-secrets">No secrets available</p>
                    )}
                </div>

                <div className="secret-details-panel">
                    {selectedSecret ? (
                        renderSecretDetails(secrets.find(s => s.id === selectedSecret))
                    ) : (
                        <div className="select-message">
                            <p>Select a secret to view details</p>
                        </div>
                    )}
                </div>
            </div>

            <style jsx>{`
                .secrets-container {
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                }
                
                .error-message {
                    color: red;
                    padding: 10px;
                    background-color: #ffe6e6;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }
                
                .secrets-layout {
                    display: flex;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                }
                
                .secrets-list {
                    width: 40%;
                    border-right: 1px solid #ddd;
                    background-color: #f9f9f9;
                }
                
                .secrets-list h2 {
                    padding: 15px;
                    margin: 0;
                    border-bottom: 1px solid #ddd;
                    background-color: #f1f1f1;
                }
                
                .secrets-list ul {
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }
                
                .secret-item {
                    padding: 12px 15px;
                    border-bottom: 1px solid #eee;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    transition: background-color 0.2s;
                }
                
                .secret-item:hover {
                    background-color: #f0f0f0;
                }
                
                .secret-item.selected {
                    background-color: #e3f2fd;
                }
                
                .secret-icon {
                    font-size: 20px;
                    margin-right: 12px;
                }
                
                .secret-title {
                    flex-grow: 1;
                    font-weight: 500;
                }
                
                .secret-type {
                    color: #666;
                    font-size: 12px;
                    text-transform: uppercase;
                    margin-left: 8px;
                }
                
                .secret-details-panel {
                    width: 60%;
                    padding: 20px;
                    background-color: #fff;
                }
                
                .secret-detail h3 {
                    margin-top: 0;
                    padding-bottom: 10px;
                    border-bottom: 1px solid #eee;
                }
                
                .secret-info p {
                    margin: 10px 0;
                    padding: 8px 0;
                }
                
                .secret-info strong {
                    display: inline-block;
                    width: 100px;
                    color: #555;
                }
                
                .select-message {
                    display: flex;
                    height: 200px;
                    justify-content: center;
                    align-items: center;
                    color: #999;
                    font-style: italic;
                }
                
                .no-secrets {
                    padding: 20px;
                    text-align: center;
                    color: #666;
                }
            `}</style>
        </div>
    );
};

export default Secrets;