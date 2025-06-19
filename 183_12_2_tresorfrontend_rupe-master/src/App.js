import React, {useState} from 'react';
import {BrowserRouter, Route, Routes} from "react-router-dom";
import './App.css';
import './css/mvp.css';
import Home from './pages/Home';
import Layout from "./pages/Layout";
import NoPage from "./pages/NoPage";
import Users from './pages/user/Users';
import LoginUser from "./pages/user/LoginUser";
import RegisterUser from "./pages/user/RegisterUser";
import Secrets from "./pages/secret/Secrets";
import NewCredential from "./pages/secret/NewCredential";
import NewCreditCard from "./pages/secret/NewCreditCard";
import NewNote from "./pages/secret/NewNote";
import ResetPasswordRequest from "./pages/user/ResetPasswordRequest";
import ResetPassword from "./pages/user/ResetPassword";
import OAuth2RedirectHandler from "./pages/user/OAuth2RedirectHandler";
import SetupMFA from "./pages/user/SetupMFA";

/**
 * App
 * @author Peter Rutschmann
 */
function App() {
    const [loginValues, setLoginValues] = useState({
        email: "",
        password: "",
        mfaToken: "",
    });
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<Layout loginValues={loginValues}/>}>
                    <Route index element={<Home/>}/>
                    <Route path="/user/users" element={<Users loginValues={loginValues}/>}/>
                    <Route path="/user/login" element={<LoginUser loginValues={loginValues} setLoginValues={setLoginValues}/>}/>
                    <Route path="/user/register" element={<RegisterUser loginValues={loginValues} setLoginValues={setLoginValues}/>}/>
                    <Route path="/secret/secrets" element={<Secrets loginValues={loginValues}/>}/>
                    <Route path="/secret/newcredential" element={<NewCredential loginValues={loginValues}/>}/>
                    <Route path="/secret/newcreditcard" element={<NewCreditCard loginValues={loginValues}/>}/>
                    <Route path="/secret/newnote" element={<NewNote loginValues={loginValues}/>}/>
                    <Route path="/reset-password-request" element={<ResetPasswordRequest/>}/>
                    <Route path="/reset-password" element={<ResetPassword />} />
                    <Route path="*" element={<NoPage/>}/>
                    <Route path="/oauth2/redirect" element={<OAuth2RedirectHandler setLoginValues={setLoginValues}/>} />
                    <Route path="/setup-mfa" element={<SetupMFA />} />
                </Route>
            </Routes>
        </BrowserRouter>
    )
}

export default App;