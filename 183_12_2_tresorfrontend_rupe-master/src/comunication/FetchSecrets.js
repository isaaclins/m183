/**
 * Fetch methodes for secret api calls
 * @author Peter Rutschmann
 */

//Post secret to server
export const postSecret = async (secretPayload) => {
    const protocol = process.env.REACT_APP_API_PROTOCOL; // "http"
    const host = process.env.REACT_APP_API_HOST; // "localhost"
    const port = process.env.REACT_APP_API_PORT; // "8080"
    const path = process.env.REACT_APP_API_PATH; // "/api"
    const portPart = port ? `:${port}` : ''; // port is optional
    const API_URL = `${protocol}://${host}${portPart}${path}`;
    console.log("Payload in postSecret:", secretPayload)

    try {
        const response = await fetch(`${API_URL}/secrets`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: secretPayload.email,
                encryptPassword: secretPayload.encryptPassword,
                content: secretPayload.content
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
    const protocol = process.env.REACT_APP_API_PROTOCOL;
    const host = process.env.REACT_APP_API_HOST;
    const port = process.env.REACT_APP_API_PORT;
    const path = process.env.REACT_APP_API_PATH;
    const portPart = port ? `:${port}` : '';
    const API_URL = `${protocol}://${host}${portPart}${path}`;
    
    console.log("Attempting to fetch secrets with credentials:", {
        email: loginValues.email,
        // Not showing password for security
    });
    
    try {
        // Use the same encryption password that was used when creating secrets
        const requestBody = {
            email: loginValues.email,
            encryptPassword: loginValues.password // Use login password for consistency
        };
        
        console.log("Sending request body for getSecrets:", {
            email: requestBody.email,
            // Not showing password for security
        });
        
        const response = await fetch(`${API_URL}/secrets/byemail`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        console.log("Raw response status:", response.status);
        console.log("Raw response headers:", [...response.headers.entries()]);
        
        const responseText = await response.text();
        console.log("Raw response body:", responseText);
        
        if (!response.ok) {
            let errorData;
            try {
                errorData = JSON.parse(responseText);
            } catch (e) {
                errorData = { message: responseText };
            }
            console.error("Response error data:", errorData);
            throw new Error(errorData.message || 'Server response failed.');
        }
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (e) {
            console.error("Failed to parse response as JSON:", e);
            throw new Error('Invalid response format from server');
        }
        
        console.log('Secrets successfully retrieved:', data);
        return data;
    } catch (error) {
        console.error('Failed to get secrets:', error);
        throw new Error('Failed to get secrets: ' + error.message);
    }
};
