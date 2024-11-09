const express = require('express');
const dotenv = require('dotenv');
const fs = require('fs');
const https = require('https');
const session = require('express-session');
const escapeHtml = require('escape-html');
const { auth, requiresAuth } = require('express-openid-connect');
const cookieParser = require('cookie-parser');

dotenv.config();

const app = express();
const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 3000;

const sslOptions = {
    key: fs.readFileSync('./server.key'),
    cert: fs.readFileSync('./server.cert')
};
  
if (externalUrl) {
    const hostname = '0.0.0.0';
    app.listen(port, hostname, () => {
    console.log(`Server locally running at http://${hostname}:${port}/ and from outside on ${externalUrl}`);    
    });
} else {
    https.createServer(sslOptions, app)
    .listen(port, () => {
        console.log(`Server running at https://localhost:${port}/`);
    });
}

const authConfig = {
    authRequired: false,
    auth0Logout: true,
    secret: process.env.AUTH0_SECRET,
    baseURL: process.env.BASE_URL,
    clientID: process.env.AUTH0_CLIENT_ID,
    issuerBaseURL: process.env.AUTH0_DOMAIN
};

app.use(auth(authConfig));

app.use(express.urlencoded({ extended: true }));
app.use(session({ 
    secret: 'tajna', 
    resave: false, 
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
    },
 }));
app.use(cookieParser());

let xssEnabled = false;
let accessControlEnabled = false;

app.get('/', (req, res) => {
    const userInput = req.cookies.userInput || 'No cookie found';
    const sanitizedUserInput = escapeHtml(userInput);
    const displayedUserInput = xssEnabled ? userInput : sanitizedUserInput;
    
    const isAuthenticated = req.oidc.isAuthenticated();
    const user = req.oidc.user;
    
    res.cookie('userInput', sanitizedUserInput, { 
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
    });

    if (!req.session.user) {
        req.session.user = `user${Math.random().toString(36).substring(7)}`;
    }
    console.log('Jedinstveni ID korisnika: ', req.session.user);

    res.send(`
        <h1>Sigurnosne ranjivosti</h1>

        <div>
            <h2>XSS Napad</h2>
            <h4>Podaci o kolačiću i sesiji :</h4>
            <p>${displayedUserInput}</p>
            <form action="/setcookie" method="POST">
                <label for="userInput">Unesite podatke:</label>
                <input type="text" id="userInput" name="userInput" required>
                <button type="submit">Unesi</button>
            </form>
            <input type="checkbox" id="xssSwitch" ${xssEnabled ? 'checked' : ''} onchange="toggleXSS()"> 
            <label for="xssSwitch">Omogući XSS ranjivost</label>
        </div>

        <div>
            <h2>Loša kontrola pristupa</h2>
            ${isAuthenticated 
                ? `<p>Prijavljeni ste kao ${user.name}</p>
                   <a href="/logout">Odjava</a>`
                : `<a href="/login">Prijava</a>`
            }
            <div>
            <br>
            <a href="/admin">Idi na admin stranicu</a>
            </div>
            <br>
            <input type="checkbox" id="accessControlSwitch" ${accessControlEnabled ? 'checked' : ''} onchange="toggleAccessControl()">
            <label for="accessControlSwitch">Omogući ranjivost loše kontrole pristupa</label>
        </div>

        <script>
            function toggleXSS() {
                fetch('/toggle-xss');
            }
            function toggleAccessControl() {
                fetch('/toggle-access-control');
            }
        </script>
    `);
});

app.get('/toggle-xss', (req, res) => {
    xssEnabled = !xssEnabled;
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.oidc.logout({ returnTo: process.env.BASE_URL });
});

app.get('/login', (req, res) => {
    if (!req.oidc.isAuthenticated()) {
        res.oidc.login();
    } else {
        res.redirect('/');
    }
});

app.get('/toggle-admin', (req, res) => {
    req.session.isAdmin = !req.session.isAdmin;
    res.redirect('/');
});

app.get('/toggle-access-control', (req, res) => {
    accessControlEnabled = !accessControlEnabled;
    res.redirect('/');
});

function isAdmin(req, res, next) {
    if (accessControlEnabled) {
        return next();
    }
    const roles = req.oidc.user['https://lab2/roles'];
    
    if (!roles || !roles.includes('admin')) {
        return res.status(403).send('Pristup zabranjen: Nemate pravo pristupa ovoj stranici.');
    }
    next();
}

app.get('/admin', requiresAuth(), isAdmin, (req, res) => {
    res.send(`
        <h1>Admin stranica</h1>
        <p>Osjetljivi podaci dostupni samo administratorima.</p>
        <a href="/">Povratak na početnu stranicu</a>
    `);
});

app.post('/setcookie', (req, res) => {
    const { userInput } = req.body;
    res.cookie('userInput', userInput, { httpOnly: false });
    res.redirect('/');
});
