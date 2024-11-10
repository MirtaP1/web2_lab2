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

app.use(function (req, res, next) {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

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
        <h1>Sigurnosni napadi</h1>

        <div>
            <h2>XSS Napad</h2>
            <p style="font-size: 0.8em; line-height: 1.1em; margin-bottom: 10px; padding: 8px; border: 1px solid #000000;">Upute:<br>
            Kada checkbox nije označen, uneseni podaci su zaštićeni od xxs napada<br>
            Kada je checkbox označen, uneseni podaci nisu zaštićeni od xxs napada<br>
            Npr. kada checkbox nije označen i korisnik unese podatke, unos korisnika je ispisan ispod podaci o kolačiću i unos je zaštićen od xxs napada<br>
            Npr. kada checkbox nije označen i korisnik unese podatke, unos korisnika prikazuje se direktno na stranici i dolazi do xxs napada</p>
            <h4>Podaci o kolačiću:</h4>
            <p>${displayedUserInput}</p>
            <form action="/setcookie" method="POST">
                <label for="userInput">Unesite podatke:</label>
                <input type="text" id="userInput" name="userInput" required>
                <button type="submit">Unesi</button>
            </form>
            <input type="checkbox" id="xssSwitch" ${xssEnabled ? 'checked' : ''} onchange="toggleXSS()"> 
            <label for="xssSwitch">Omogući XSS ranjivost</label>
        </div>
        <p style="border: 1px dashed #000000; margin: 20px 0;"></p>
        <div>
            <h2>Loša kontrola pristupa</h2>
            <p style="font-size: 0.8em; line-height: 1.1em; margin-bottom: 10px; padding: 8px; border: 1px solid #000000;">Upute: <br>
            Kada checkbox nije označen, uneseni podaci su zaštićeni od ranjivost loše kontrole pristupa<br>
            Kada je checkbox označen, uneseni podaci nisu zaštićeni od ranjivost loše kontrole pristupa<br>
            Korisnik se može prijaviti klikom na Prijava, ako je korisnik prijavljen piše Prijavljeni ste kao “email korisnika”, klikom na Odjava korisnik se odjavi<br>
            Ako korisnik klikne na Idi na admin stranicu, a nije prijavljen traži se od njega prijava prije nego ga se preusmjeri na admin stranicu<br>
            Ako korisnik klikne na Idi na admin stranicu, a prijavljen je, korisnika se preusmjeri na admin stranicu<br>
            Ako checkbox nije označen i korisnik je admin, prikazuju mu se podaci na admin stranici<br>
            Ako checkbox nije označen i korisnik nije admin, ne prikazuju mu se podaci na admin stranici nego dolazi do greške 403 i prikazuje mu se poruka o zabranjenom pristupu<br>
            Ako je checkbox označen i korisnik je admin, prikazuju mu se podaci na admin stranici<br>
            Ako je checkbox označen i korisnik nije admin, prikazuju mu se podaci na admin stranici<br>
            </p>
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
    res.cookie('userInput', userInput, { httpOnly: !xssEnabled });
    res.redirect('/');
});
