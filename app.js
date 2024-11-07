const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Povezivanje na bazu podataka
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: true,
    name: 'customSessionID',
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 600000
    },
    genid: () => crypto.randomBytes(16).toString('hex')
}));

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// SQL Injection toggle on login
app.post('/login', async (req, res) => {
    const { username, password, enableInjection } = req.body;
    console.log('Enable Injection:', enableInjection); // Dodani ispis za provjeru
    let query;

    if (enableInjection === 'on') {
        // Ranljiv upit (SQL Injection)
        query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    } else {
        // Siguran upit s parametrima
        query = 'SELECT * FROM users WHERE username = $1 AND password = $2';
    }

    try {
        const results = await pool.query(query, enableInjection === 'on' ? [] : [username, password]);
        if (results.rows.length > 0) {
            // Generiranje CSRF tokena nakon prijave
            const csrfToken = crypto.randomBytes(16).toString('hex');
            req.session.csrfToken = csrfToken;
            res.send(`Prijava uspješna! CSRF token: ${csrfToken}`);
        } else {
            res.send('Prijava neuspješna.');
        }
    } catch (err) {
        res.send('Greška u prijavi.');
    }
});

// Zaštićena ruta za demonstraciju CSRF
app.post('/update-data', (req, res) => {
    const { data, csrfToken } = req.body;

    if (csrfToken !== req.session.csrfToken) {
        return res.status(403).send('CSRF Zahtjev odbijen!');
    }

    res.send('Podaci ažurirani!');
});

app.listen(PORT, () => {
    console.log(`Server pokrenut na portu ${PORT}`);
});
