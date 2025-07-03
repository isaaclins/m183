/**
 * Fetch methods for user API calls
 * @author Peter Rutschmann
 */

/**
 * Constructs the base API URL from environment variables
 * @returns {string} The base API URL
 */
const getApiBaseUrl = () => {
    const protocol = process.env.REACT_APP_API_PROTOCOL; // "http"
    const host = process.env.REACT_APP_API_HOST; // "localhost"
    const port = process.env.REACT_APP_API_PORT; // "8080"
    const path = process.env.REACT_APP_API_PATH; // "/api"
    const portPart = port ? `:${port}` : ''; // port is optional
    return `${protocol}://${host}${portPart}${path}`;
};

/**
 * Gets all users from the API
 * @returns {Promise<Array>} Promise resolving to array of users
 * @throws {Error} Error with message if fetching fails
 */
export const getUsers = async () => {
    const API_URL = getApiBaseUrl();
    
    try {
        const response = await fetch(`${API_URL}/users`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });

        // Parse response even if not OK to get error details
        const data = await response.json().catch(() => ({}));
        
        if (!response.ok) {
            // Handle structured error messages from backend
            if (data.message) {
                if (Array.isArray(data.message)) {
                    throw new Error(data.message.join(', '));
                } else {
                    throw new Error(data.message);
                }
            }
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        
        console.log('Users successfully retrieved:', data);
        return data;
    } catch (error) {
        console.error('Failed to get users:', error);
        
        // Return a more specific error with response data if available
        if (error.response) {
            throw error; // Re-throw our custom error with response data
        } else {
            throw new Error(`Failed to get users: ${error.message}`);
        }
    }
};

/**
 * Posts a new user to the API
 * @param {Object} content User data to post
 * @returns {Promise<Object>} Promise resolving to created user data
 * @throws {Error} Error with message if posting fails
 */
export const postUser = async (content) => {
    const API_URL = getApiBaseUrl();
    
    if (!content) {
        throw new Error('User data is required');
    }
    
    try {
        const response = await fetch(`${API_URL}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                firstName: content.firstName || '',
                lastName: content.lastName || '',
                email: content.email || '',
                password: content.password || '',
                passwordConfirmation: content.passwordConfirmation || '',
                captchaToken: content.captchaToken || ''
            })   
        });

        // Try to parse the response body as JSON
        const data = await response.json().catch(() => ({}));
        
        if (!response.ok) {
            const error = new Error('Registration failed');
            
            // Handle structured error messages from backend
            if (data.message) {
                if (Array.isArray(data.message)) {
                    error.message = data.message.join(', ');
                } else {
                    error.message = data.message;
                }
            } else {
                error.message = `Server returned ${response.status}: ${response.statusText}`;
            }
            
            // Attach response data for more context
            error.response = {
                status: response.status,
                data: data
            };
            
            throw error;
        }
        
        console.log('User successfully posted:', data);
        return data;
    } catch (error) {
        console.error('Failed to post user:', error);
        
        // If it's already our custom error with response data, rethrow it
        if (error.response) {
            throw error;
        } else {
            // Create a generic error for network issues or other problems
            throw new Error(`Failed to save user: ${error.message}`);
        }
    }
};