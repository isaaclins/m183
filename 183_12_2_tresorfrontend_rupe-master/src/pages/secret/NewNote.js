import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {postSecret} from "../../comunication/FetchSecrets";

/**
 * NewNote
 * @author Peter Rutschmann
 */
function NewNote({loginValues}) {
    const initialState = {
        kindid: 3,
        kind:"note",
        title: "",
        content: "",
    };
    const [noteValues, setNoteValues] = useState(initialState);
    const [errorMessage, setErrorMessage] = useState('');

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setErrorMessage('');
        try {
            const content = noteValues;
            await postSecret({loginValues, content});
            setNoteValues(initialState);
            navigate('/secret/secrets');
        } catch (error) {
            console.error('Failed to fetch to server:', error.message);
            setErrorMessage(error.message);
        }
    };

    return (
        <div>
            <h2>Add new note secret</h2>
            <form onSubmit={handleSubmit}>
                <section>
                    <aside>
                        <div>
                            <label>title:</label>
                            <input
                                type="text"
                                value={noteValues.title}
                                onChange={(e) =>
                                    setNoteValues(prevValues => ({...prevValues, title: e.target.value}))}
                                required
                                placeholder="Please enter a title *"
                            />
                        </div>
                        <div>
                            <label>content:</label>
                            <textarea
                                rows={4}
                                style={{
                                    resize: 'both', // Ermöglicht Größenänderung in beide Richtungen
                                    width: '24%', // Standardbreite (kann angepasst werden)
                                    minWidth: '190px', // Minimale Breite
                                    minHeight: '100px', // Minimale Höhe
                                }}
                                value={noteValues.content}
                                onChange={(e) =>
                                    setNoteValues(prevValues =>
                                        ({...prevValues, content: e.target.value}))}
                                required
                                placeholder="Please enter a content *"
                            />
                        </div>
                        <button type="submit">Save secret</button>
                        {errorMessage && <p style={{color: 'red'}}>{errorMessage}</p>}
                    </aside>
                </section>
            </form>
        </div>
    );
}

export default NewNote;
