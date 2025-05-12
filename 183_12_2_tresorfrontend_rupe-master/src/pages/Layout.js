import { Outlet, Link } from "react-router-dom";

/**
 * Layout
 * @author Peter Rutschmann
 */
const Layout = ({loginValues}) => {
    return (
        <>
            <nav>
                <h1>The secret tresor application</h1>
                <p>{loginValues.email === '' ? 'No user logged in' : 'user:' + loginValues.email}</p>
                <ul>
                    <li><a href="/">Secrets</a>
                    <ul>
                        <li><Link to="/secret/secrets">my secrets</Link></li>
                        <li><Link to="/secret/newcredential">new credential</Link></li>
                        <li><Link to="/secret/newcreditcard">new credit-card</Link></li>
                        <li><Link to="/secret/newnote">new note</Link></li>
                    </ul>
                    </li>
                    <li><a href="/">User</a>
                    <ul>
                        <li><Link to="/user/login">login</Link></li>
                        <li><Link to="/user/register">register</Link></li>
                    </ul>
                    </li>
                    <li><a href="/">Admin</a>
                        <ul>
                            <li><Link to="/user/users">All users</Link></li>
                            <li>Add user</li>
                            <li><Link to="/user/users/:id">Edit user</Link></li>
                            <li>All secrets</li>
                        </ul>
                    </li>
                    <li>
                        <Link to="/">About</Link>
                    </li>
                </ul>
            </nav>
            <hr/>
            <Outlet/>
        </>
    )
};

export default Layout;