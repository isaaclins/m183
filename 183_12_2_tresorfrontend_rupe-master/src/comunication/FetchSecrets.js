/**
 * Fetch methodes for secret api calls
 * @author Peter Rutschmann
 */

//Post secret to server
export const postSecret = async ({loginValues, content}) => {
    const protocol = process.env.REACT_APP_API_PROTOCOL; // "http"
    const host = process.env.REACT_APP_API_HOST; // "localhost"
    const port = process.env.REACT_APP_API_PORT; // "8080"
    const path = process.env.REACT_APP_API_PATH; // "/api"
    const portPart = port ? `:${port}` : ''; // port is optional
    const API_URL = `${protocol}://${host}${portPart}${path}`;
    console.log(loginValues)

    try {
        const response = await fetch(`${API_URL}/secrets`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: loginValues.email,
                encryptPassword: loginValues.password,
                content: content
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Server response failed.');
        }

        const data = await response.json();
        console.log('Secret successfully posted:', data);
        return data;
    } catch (error) {
        console.error('Error posting secret:', error.message);
        throw new Error('Failed to save secret. ' || error.message);
    }
};

//get all secrets for a user identified by its email
export const getSecretsforUser = async (loginValues) => {
    const protocol = process.env.REACT_APP_API_PROTOCOL; // "http"
    const host = process.env.REACT_APP_API_HOST; // "localhost"
    const port = process.env.REACT_APP_API_PORT; // "8080"
    const path = process.env.REACT_APP_API_PATH; // "/api"
    const portPart = port ? `:${port}` : ''; // port is optional
    const API_URL = `${protocol}://${host}${portPart}${path}`;

    try {
        const response = await fetch(`${API_URL}/secrets/byemail`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: loginValues.email,
                encryptPassword: loginValues.password
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Server response failed.');
        }
        const data = await response.json();
        console.log('Secret successfully got:', data);
        return data;
    } catch (error) {
        console.error('Failed to get secrets:', error.message);
        throw new Error('Failed to get secrets. ' || error.message);
    }
};

//delete secret for a user
export const deleteSecret = async ({ secretId, loginValues }) => {
    const protocol = process.env.REACT_APP_API_PROTOCOL;
    const host = process.env.REACT_APP_API_HOST;
    const port = process.env.REACT_APP_API_PORT;
    const path = process.env.REACT_APP_API_PATH;
    const portPart = port ? `:${port}` : '';
    const API_URL = `${protocol}://${host}${portPart}${path}`;

    console.log(`Attempting to delete secret ID: ${secretId} for user: ${loginValues.email}`);

    try {
        const response = await fetch(`${API_URL}/secrets/${secretId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            // Send credentials in the body for password verification on the backend
            body: JSON.stringify({
                email: loginValues.email,
                encryptPassword: loginValues.password
            })
        });

        if (!response.ok) {
            // Try to parse error message from backend
            let errorMsg = 'Server response failed.';
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorData.answer || errorMsg;
            } catch (parseError) {
                // If parsing fails, use the status text
                errorMsg = response.statusText;
            }
             console.error(`Error deleting secret: ${response.status} ${errorMsg}`);
            throw new Error(errorMsg);
        }

        // Check if response has content before parsing JSON
        const responseText = await response.text(); // Read response text
        let data = {};
        if (responseText) {
             try {
                 data = JSON.parse(responseText);
             } catch (jsonError) {
                 console.error('Error parsing delete response JSON:', jsonError);
                 // Use the text response if JSON parsing fails but status was OK
                 data = { message: responseText };
             }
        } else {
             // Handle empty response for successful DELETE
             data = { message: 'Secret successfully deleted' };
        }

        console.log('Secret successfully deleted:', data);
        return data; // Return success data/message
    } catch (error) {
        console.error('Failed to delete secret:', error.message);
        // Re-throw the error to be caught by the calling component
        throw new Error(error.message || 'Failed to delete secret.');
    }
};
