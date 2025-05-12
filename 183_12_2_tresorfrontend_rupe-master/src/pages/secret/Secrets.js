import '../../App.css';
import React, {useEffect, useState, useCallback} from 'react';
import {getSecretsforUser, deleteSecret} from "../../comunication/FetchSecrets";

/**
 * Component to render secret content based on its kind.
 */
const SecretContent = ({ content }) => {
    let parsedContent;
    try {
        // The content from the backend is already decrypted (as a JSON string),
        // so we parse it here.
        parsedContent = JSON.parse(content);
    } catch (e) {
        console.error("Failed to parse secret content:", content, e);
        // Display raw content if parsing fails (might be old format or error)
        return <pre>{content}</pre>;
    }

    switch (parsedContent.kind) {
        case 'credential':
            return (
                <div>
                    <strong>Username:</strong> {parsedContent.userName}<br />
                    <strong>Password:</strong> {parsedContent.password} <span style={{ fontStyle: 'italic' }}>(Displayed for demo, hide in real app)</span><br />
                    <strong>URL:</strong> {parsedContent.url}
                </div>
            );
        case 'creditcard':
            return (
                <div>
                    <strong>Type:</strong> {parsedContent.cardtype}<br />
                    <strong>Number:</strong> {parsedContent.cardnumber}<br />
                    <strong>Expiration:</strong> {parsedContent.expiration}<br />
                    <strong>CVV:</strong> {parsedContent.cvv} <span style={{ fontStyle: 'italic' }}>(Displayed for demo, hide in real app)</span>
                </div>
            );
        case 'note':
            return (
                <div>
                    <strong>Title:</strong> {parsedContent.title}<br />
                    <strong>Note:</strong> <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{parsedContent.content}</pre>
                </div>
            );
        default:
            // Fallback for unknown kinds or if content is not an object with 'kind'
            return <pre>{JSON.stringify(parsedContent, null, 2)}</pre>;
    }
};

/**
 * Secrets List Page
 * @author Peter Rutschmann
 * @author Gemini (Refactoring for Delete & Typed Display)
 */
const Secrets = ({loginValues}) => {
    const [secrets, setSecrets] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState('');

    // Use useCallback to memoize fetchSecrets function
    const fetchSecrets = useCallback(async () => {
        setErrorMessage('');
        if (!loginValues || !loginValues.email || !loginValues.password) {
            console.error('Secrets: Invalid login credentials.', loginValues);
            setErrorMessage("Login required to view secrets.");
            setSecrets([]); // Clear secrets if not logged in
            return;
        }
        setIsLoading(true);
        try {
            const data = await getSecretsforUser(loginValues);
            console.log('Fetched secrets:', data);
            setSecrets(data || []); // Ensure secrets is always an array
        } catch (error) {
            console.error('Failed to fetch secrets:', error.message);
            setErrorMessage(`Failed to fetch secrets: ${error.message}`);
            setSecrets([]); // Clear secrets on error
        } finally {
             setIsLoading(false);
        }
    }, [loginValues]); // Dependency: re-fetch if loginValues change

    useEffect(() => {
        fetchSecrets();
    }, [fetchSecrets]); // Run fetchSecrets when the component mounts or fetchSecrets changes

    const handleDelete = async (secretId) => {
        // Optional: Add a confirmation dialog
        if (!window.confirm(`Are you sure you want to delete secret ${secretId}?`)) {
            return;
        }

        setErrorMessage(''); // Clear previous errors
        setIsLoading(true); // Indicate loading state
        try {
            await deleteSecret({ secretId, loginValues });
            // Refresh the list after successful deletion
            // OPTION 1: Re-fetch the entire list
            // await fetchSecrets();

            // OPTION 2: Remove the item directly from the state (more responsive)
            setSecrets(currentSecrets => currentSecrets.filter(secret => secret.id !== secretId));

            console.log(`Secret ${secretId} deleted successfully.`);

        } catch (error) {
            console.error(`Failed to delete secret ${secretId}:`, error.message);
            setErrorMessage(`Failed to delete secret: ${error.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <>
            <h1>My Secrets</h1>
            {isLoading && <p>Loading...</p>}
            {errorMessage && <p style={{color: 'red'}}>{errorMessage}</p>}
             <div> {/* Changed from form to div as it's mainly display */} 
                <h2>Secrets List</h2>
                <table border="1" style={{ width: '100%', tableLayout: 'fixed' }}>
                    <thead>
                    <tr>
                        <th style={{ width: '10%' }}>ID</th>
                        {/*<th>User ID</th> We know it's the logged in user's secrets */} 
                        <th style={{ width: '70%' }}>Content</th>
                        <th style={{ width: '20%' }}>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {secrets?.length > 0 ? (
                        secrets.map(secret => (
                            <tr key={secret.id}>
                                <td>{secret.id}</td>
                                {/*<td>{secret.userId}</td>*/} 
                                <td style={{ wordWrap: 'break-word' }}>
                                    {/* Use the new component to render content */} 
                                    <SecretContent content={secret.content} />
                                </td>
                                <td>
                                    {/* Add Delete Button */} 
                                    <button
                                        onClick={() => handleDelete(secret.id)}
                                        disabled={isLoading} // Disable button while loading
                                        style={{ cursor: isLoading ? 'not-allowed' : 'pointer' }}
                                    >
                                        Delete
                                    </button>
                                    {/* Add Edit button placeholder/link here if needed */}
                                </td>
                            </tr>
                        ))
                    ) : (
                        <tr>
                            <td colSpan="3" style={{ textAlign: 'center' }}>
                                {isLoading ? 'Loading...' : 'No secrets available'}
                            </td>
                        </tr>
                    )}
                    </tbody>
                </table>
            </div>
        </>
    );
};

export default Secrets;
