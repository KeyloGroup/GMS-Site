const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const axios = require('axios');
const session = require('express-session');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const { version } = require('os');
const { Pool } = require('pg');
const { parseISO, startOfDay, endOfDay, addDays } = require("date-fns");
const querystring = require('querystring');
const unless = require('express-unless');

require('dotenv').config({ path: '/root/KeyloENV/.env' });
console.log("ðŸ” ROBLOX_OAUTH_CLIENT_SECRET:", process.env.ROBLOX_OAUTH_CLIENT_SECRET ? "LOADED" : "MISSING");

dotenv.config();
const app = express();
const PORT = 3000;

const AccountsPool = new Pool({
  connectionString: process.env.PG_URL
});

const AccountsBannedPool = new Pool({
  connectionString: process.env.PG_URL
});

AccountsPool.connect()
  .then(c => { console.log("âœ… Connected to PostgreSQL"); c.release(); })
  .catch(err => console.error("âŒ PostgreSQL connection error:", err));


app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(csurf({ cookie: true }));

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 100 * 60 * 60 * 24 * 30,
    },
  })
);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


app.get("/auth/roblox", (req, res) => {
  const clientId = process.env.ROBLOX_OAUTH_CLIENT_ID;
  const redirectUri = process.env.ROBLOX_OAUTH_REDIRECT_URI;
  const scope = ["openid", "profile"].join(" ");
  const state = crypto.randomBytes(16).toString("hex");

  req.session.oauthState = state;

  const authUrl =
    `https://apis.roblox.com/oauth/v1/authorize?` +
    querystring.stringify({
      client_id: clientId,
      response_type: "code",
      redirect_uri: redirectUri,
      scope,
      state
    });

  res.redirect(authUrl);
});

app.get("/auth/roblox/callback", async (req, res, next) => {
  try {
    const cookieOptions = {
      secure: true,
      sameSite: "lax"
    };

    ["id", "username", "avatar"].forEach((c) => {
      res.clearCookie(c, { ...cookieOptions, domain: ".keyloroblox.xyz" });
      res.clearCookie(c, { ...cookieOptions, domain: "app.keyloroblox.xyz" });
    });

    const { code, state, error, error_description } = req.query;

    if (error) return res.status(400).send(`OAuth error: ${error_description || error}`);
    if (!state || state !== req.session.oauthState)
      return res.status(400).send("Invalid OAuth state");

    const tokenRes = await axios.post(
      "https://apis.roblox.com/oauth/v1/token",
      querystring.stringify({
        grant_type: "authorization_code",
        client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
        client_secret: process.env.ROBLOX_OAUTH_CLIENT_SECRET,
        code,
        redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token } = tokenRes.data;

    const userRes = await axios.get(
      "https://apis.roblox.com/oauth/v1/userinfo",
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;

    const { rows: bannedRows } = await AccountsBannedPool.query(
      'SELECT * FROM "AccountsBan" WHERE username = $1 LIMIT 1',
      [robloxUsername]
    );

    if (bannedRows.length > 0) {
      const ban = bannedRows[0];
      return res.redirect(
        `https://app.keyloroblox.xyz/account/restricted?reason=${encodeURIComponent(ban.reason || "No reason")}`
      );
    }

    const { rows: userRows } = await AccountsPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1',
      [robloxUsername]
    );

    res.cookie("id", robloxId, {
      ...cookieOptions,
      domain: ".keyloroblox.xyz"
    });

    res.cookie("username", robloxUsername, {
      ...cookieOptions,
      domain: ".keyloroblox.xyz"
    });

    res.cookie("avatar", avatarUrl, {
      ...cookieOptions,
      domain: ".keyloroblox.xyz"
    });

    if (userRows.length > 0) {
      return res.redirect("https://app.keyloroblox.xyz/");
    }

    req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
    return res.redirect("/register?oauth=success");

  } catch (err) {
    next(err);
  }
});

app.use(express.static(path.join(__dirname, 'public')));


app.get('/', (req, res) => {
  res.render('index', { title: 'Keylo' });
});

app.get('/register', (req, res) => {
  const pending = req.session.pendingRoblox;

  if (req.query.oauth === 'success' && pending) {
    return res.render('passwordregister', {
      title: 'Keylo - Complete Registration',
      csrfToken: req.csrfToken(),
      robloxUsername: pending.robloxUsername,
      avatarUrl: pending.avatarUrl
    });
  }

  res.render('register', {
    title: 'Keylo - Register',
    csrfToken: req.csrfToken()
  });
});

app.get('/login', (req, res) => {
  res.render('login', {
    csrfToken: req.csrfToken(),
    oauthSuccess: req.query.oauth === 'success',
    robloxUsername: req.query.username || '',
    robloxId: req.query.id || ''
  });
});


app.post('/api/register', async (req, res) => {
  try {
    const { robloxUsername, password } = req.body;

    const { rows: existing } = await AccountsPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1',
      [robloxUsername]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: "Account already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await AccountsPool.query(
      'INSERT INTO "Accounts" ("roblox username", "hashed password") VALUES ($1, $2)',
      [robloxUsername, hashedPassword]
    );

    return res.redirect("https://app.keyloroblox.xyz");

  } catch (err) {
    return res.status(500).send("Server error during registration");
  }
});


app.post('/login', async (req, res) => {
  try {
    const { robloxUsername, password } = req.body;

    const { rows: users } = await AccountsPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1',
      [robloxUsername]
    );

    if (!users.length) {
      return res.status(400).json({ error: 'User not found' });
    }

    const match = await bcrypt.compare(password, users[0]["hashed password"]);
    if (!match) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    return res.redirect("https://app.keyloroblox.xyz");

  } catch (err) {
    return res.status(500).send("Server error during login");
  }
});

app.use((req, res) => {
  res.status(404).render("404");
});


app.listen(PORT, () => {
  console.log(`âœ… Server running at http://localhost:${PORT}`);
});
