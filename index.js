const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const axios = require ('axios');
const session = require('express-session');
const mysql = require('mysql2/promise');

dotenv.config();

const app = express();
const PORT = 3000;

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_Name,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

app.use(cookieParser());

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(csurf({ cookie: true }));

// --- PAGES --- \\

app.get('/', (req, res) => {
    res.render('index', {
        title: "Keylo"
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
