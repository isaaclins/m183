import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {postSecret} from "../../comunication/FetchSecrets";

/**
 * NewCreditCard
 * @author Peter Rutschmann
 */
function NewCreditCard({loginValues}) {
    const initialState = {
        kindid: 2,
        kind:"creditcard",
        cardtype: "",
        cardnumber: "",
        expiration: "",
        cvv: ""
    };
    const [creditCardValues, setCreditCardValues] = useState(initialState);
    const [errorMessage, setErrorMessage] = useState('');

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setErrorMessage('');
        try {
            const content = creditCardValues;
            await postSecret({loginValues, content});
            setCreditCardValues(initialState);
            navigate('/secret/secrets');
        } catch (error) {
            console.error('Failed to fetch to server:', error.message);
            setErrorMessage(error.message);
        }
    };

    return (
        <div>
            <h2>Add new credit-card secret</h2>
            <form onSubmit={handleSubmit}>
                <section>
                    <aside>
                        <div>
                            <label>card type:</label>
                            <select
                                value={creditCardValues.cardtype}
                                onChange={(e) =>
                                    setCreditCardValues((prevValues) => ({
                                        ...prevValues,
                                        cardtype: e.target.value,
                                    }))}
                                required
                            >
                                <option value="" disabled>
                                    Please select card type
                                </option>
                                <option value="Visa">Visa</option>
                                <option value="Mastercard">Mastercard</option>
                            </select>
                        </div>
                        <div>
                            <label>cardnumber:</label>
                            <input
                                type="text"
                                value={creditCardValues.cardnumber}
                                onChange={(e) =>
                                    setCreditCardValues(prevValues => ({...prevValues, cardnumber: e.target.value}))}
                                required
                                placeholder="Please enter cardnumber"
                            />
                        </div>
                        <div>
                            <label>expiration (mm/yy):</label>
                            <input
                                type="text"
                                value={creditCardValues.expiration}
                                onChange={(e) =>
                                    setCreditCardValues(prevValues => ({...prevValues, expiration: e.target.value}))}
                                required
                                placeholder="Please enter expiration"
                            />
                        </div>
                        <div>
                            <label>cvv:</label>
                            <input
                                type="text"
                                value={creditCardValues.cvv}
                                onChange={(e) =>
                                    setCreditCardValues(prevValues => ({...prevValues, cvv: e.target.value}))}
                                required
                                placeholder="Please enter cvv"
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

export default NewCreditCard;
