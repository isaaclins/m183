import '../../App.css';
import React, {useEffect, useState} from 'react';
import {getSecretsforUser} from "../../comunication/FetchSecrets";

/**
 * Secrets
 * @author Peter Rutschmann
 */
const Secrets = ({loginValues}) => {
    const [secrets, setSecrets] = useState([]);
    const [errorMessage, setErrorMessage] = useState('');

    useEffect(() => {
        const fetchSecrets = async () => {
            setErrorMessage('');
            if( ! loginValues.email){
                console.error('Secrets: No valid email, please do login first:' + loginValues);
                setErrorMessage("No valid email, please do login first.");
            } else {
                try {
                    const data = await getSecretsforUser(loginValues);
                    console.log(data);
                    setSecrets(data);
                } catch (error) {
                    console.error('Failed to fetch to server:', error.message);
                    setErrorMessage(error.message);
                }
            }
        };
        fetchSecrets();
    }, [loginValues]);

    return (
        <>
            <h1>my secrets</h1>
            {errorMessage && <p style={{color: 'red'}}>{errorMessage}</p>}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <form>
                    <h2>secrets</h2>
                    <table border="1" style={{ margin: '0 auto' }}>
                        <thead>
                        <tr>
                            <th>secret id</th>
                            <th>user id</th>
                            <th>content</th>
                        </tr>
                        </thead>
                        <tbody>
                        {secrets?.length > 0 ? (
                            secrets.map(secret => (
                                <tr key={secret.id}>
                                    <td>{secret.id}</td>
                                    <td>{secret.userId}</td>
                                    <td style={{ textAlign: 'left', verticalAlign: 'top' }}>
                                        {typeof secret.content === 'string' ? (
                                            (() => {
                                                try {
                                                    const parsedContent = JSON.parse(secret.content);
                                                    return Object.entries(parsedContent).map(([key, value]) => (
                                                        <div key={key} style={{ marginBottom: '5px', padding: '2px' }}>
                                                            <strong style={{ marginRight: '5px' }}>{key}:</strong>
                                                            <span>{String(value)}</span>
                                                        </div>
                                                    ));
                                                } catch (e) {
                                                    console.error("Failed to parse secret content", e);
                                                    return <pre>{secret.content}</pre>; // Fallback to raw display
                                                }
                                            })()
                                        ) : (
                                            <pre>{JSON.stringify(secret.content, null, 2)}</pre> // Fallback for non-string content
                                        )}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="3">No secrets available</td>
                            </tr>
                        )}
                        </tbody>
                    </table>
                </form>
            </div>
        </>
    );
};

export default Secrets;
