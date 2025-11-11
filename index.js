// server.js
// Combined + updated to cookie-based auth for user identity

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
const { Client } = require('pg');
const { parseISO, startOfDay, endOfDay, addDays } = require("date-fns");
const querystring = require('querystring');
const unless = require('express-unless');
const mysql = require('mysql2/promise');

require('dotenv').config({ path: '/root/KeyloENV/.env' });
console.log("🔍 ROBLOX_OAUTH_CLIENT_SECRET:", process.env.ROBLOX_OAUTH_CLIENT_SECRET ? "LOADED" : "MISSING");

dotenv.config();
const app = express();
const PORT = 3050;

/* -------------------- SUPABASE -------------------- */
const supabaseAccounts = createClient(
    process.env.SUPABASE_ACCOUNTS_URL,
    process.env.SUPABASE_ACCOUNTS_SERVICE_ROLE_KEY
);
const supabaseWorkspaces = createClient(
    process.env.SUPABASE_WORKSPACES_URL,
    process.env.SUPABASE_WORKSPACES_SERVICE_ROLE_KEY
);

const pgClient = new Client({
    connectionString: process.env.SUPABASE_PG_URL
});

pgClient.connect((err) => {
    if (err) {
        console.error('❌ Failed to connect to Supabase PostgreSQL database:', err.stack);
    } else {
        console.log('✅ Connected to Supabase PostgreSQL database.');
    }
});

const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASS, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

// helper: get site state
async function getSiteState() {
  const [rows] = await pool.query('SELECT maintenance FROM site_state WHERE id=1');
  return rows[0] || { maintenance: 0 };
}

/* -------------------- MIDDLEWARE -------------------- */
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(csurf({ cookie: true }));

// Keep session only for ephemeral things (e.g., emoji verification code)
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
            maxAge: 1000 * 60 * 60 * 24 * 30,
        },
    })
);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

function requireAdmin(role = null) {
  return (req, res, next) => {
    const admin = req.session.admin;
    if (!admin) return res.redirect('/admin/login');
    if (role && admin.role !== role) return res.status(403).send('Forbidden');
    next();
  };
}

async function ownerExists() {
  const [rows] = await pool.query('SELECT COUNT(*) as cnt FROM admins WHERE role="owner"');
  return rows[0].cnt > 0;
}

// Step 1: Redirect user to Roblox OAuth
app.get("/auth/roblox", (req, res) => {
  const clientId = process.env.ROBLOX_OAUTH_CLIENT_ID;
  const redirectUri = process.env.ROBLOX_OAUTH_REDIRECT_URI;
  const scope = ["openid", "profile"].join(" ");
  const state = crypto.randomBytes(16).toString("hex");

  // store state in session to prevent CSRF
  req.session.oauthState = state;

  const authUrl = `https://apis.roblox.com/oauth/v1/authorize?` +
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
    const { code, state, error, error_description } = req.query;

    if (error) return res.status(400).send(`OAuth error: ${error_description || error}`);
    if (!state || state !== req.session.oauthState) return res.status(400).send("Invalid OAuth state");

    // Exchange code for tokens
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

    // Fetch user info
    const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;

    // --- CHECK SUPABASE ACCOUNTS ---
    const { data: users, error: fetchError } = await supabaseAccounts
      .from('Accounts')
      .select('*')
      .eq('roblox username', robloxUsername)
      .limit(1);

    if (fetchError) {
      console.error('❌ Supabase fetch error:', fetchError);
      return res.status(500).send('Database error');
    }

    if (users && users.length > 0) {
      // ✅ USER EXISTS → LOGIN
      const user = users[0];
      const avatar = avatarUrl || await getAvatarUrl(robloxId);

      setUserCookies(res, {
        id: robloxId,
        username: robloxUsername,
        avatar,
        theme: 'n/a'
      });

      return res.redirect("/launch");
    } else {
      // ⚠️ USER DOES NOT EXIST → STORE INFO IN SESSION, GO TO REGISTER PASSWORD STEP
      req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
      // The register page can check for pendingRoblox to pre-fill info
      return res.redirect("/register?oauth=success");
    }

  } catch (err) {
    console.error("OAuth callback error:", err.response?.data || err.message);
    return next(err);
  }
});

app.use(express.static(path.join(__dirname, 'public')));

/* -------------------- MAIL TRANSPORTS -------------------- */
const transporter = nodemailer.createTransport({
    host: process.env.MAILCOW_HOST || 'mail.keyloroblox.xyz',
    port: 465,
    secure: true,
    auth: {
        user: process.env.MAILCOW_USER || 'noreply@keyloroblox.xyz',
        pass: process.env.MAILCOW_PASS,
    },
});

const recruitmentTransporter = nodemailer.createTransport({
    host: process.env.RECRUITMENT_MAIL_HOST || 'mail.keyloroblox.xyz',
    port: 465,
    secure: true,
    auth: {
        user: process.env.RECRUITMENT_MAIL_USER || 'recruitment@keyloroblox.xyz',
        pass: process.env.RECRUITMENT_MAIL_PASS,
    },
});

/* -------------------- HELPERS -------------------- */
function setUserCookies(res, userData) {
    const cookieOptions = {
        maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
        httpOnly: false, // allow client to read username/avatar/theme
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    };
    res.cookie('user_id', userData.id, cookieOptions);
    res.cookie('username', userData.username, cookieOptions);
    res.cookie('profile_pic', userData.avatar, cookieOptions);
    res.cookie('theme', userData.theme || 'n/a', cookieOptions);
}

async function fetchRobloxUsernameById(userId) {
    const profileRes = await axios.get(`https://users.roblox.com/v1/users/${userId}`);
    return profileRes.data?.name || 'Guest';
}

function getClosestDateForWeekday(targetDayIndex) {
    const today = new Date();
    const todayIndex = today.getDay(); // 0=Sun … 6=Sat
    let diff = targetDayIndex - todayIndex;
    if (diff < 0) diff += 7;
    const date = new Date(today);
    date.setDate(today.getDate() + diff);
    return date.toISOString().split('T')[0]; // YYYY-MM-DD
}

async function getAvatarUrl(userId) {
    try {
        const thumbRes = await axios.get(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=true`
        );
        return thumbRes.data?.data?.[0]?.imageUrl || '/images/default-avatar.png';
    } catch {
        return '/images/default-avatar.png';
    }
}

async function getAvatarUrl(userId) {
    const thumbRes = await axios.get(
        `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=true`
    );
    return thumbRes.data?.data?.[0]?.imageUrl || '/images/default-avatar.png';
}

/* -------------------- API KEY HELPER FUNCTIONS (MODIFIED FOR SINGLE FIELD) -------------------- */

function generateApiKey(length = 48) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

/**
 * Encrypts the plaintext and combines IV, Tag, and Ciphertext into a single string.
 * Format used for storage in API_Key: IV:TAG:CIPHERTEXT (all base64)
 */
function encryptApiKey(text, encoding = "base64") {
    try {
        if (!process.env.API_MASTER_KEY_BASE64) {
            throw new Error("API_MASTER_KEY_BASE64 environment variable is not set.");
        }
        const masterKey = Buffer.from(process.env.API_MASTER_KEY_BASE64, "base64");
        const iv = crypto.randomBytes(16); // 16 bytes for AES-256-GCM
        const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, iv);

        let encrypted = cipher.update(text, "utf8", encoding);
        encrypted += cipher.final(encoding);
        const tag = cipher.getAuthTag().toString(encoding);

        // Concatenate IV, Tag, and Ciphertext for single-field storage
        return `${iv.toString(encoding)}:${tag}:${encrypted}`;
    } catch (err) {
        console.error("❌ Encryption failed:", err.message);
        return null;
    }
}

/**
 * Decrypts the single combined API key string (IV:TAG:CIPHERTEXT).
 * This replaces the original multi-parameter decryptApiKey function.
 */
function decryptApiKey(combinedKey, encoding = "base64") {
    try {
        if (!process.env.API_MASTER_KEY_BASE64) {
            throw new Error("API_MASTER_KEY_BASE64 environment variable is not set.");
        }
        const parts = combinedKey.split(':');
        if (parts.length !== 3) {
            console.error("❌ Decryption failed: Combined key is not in IV:TAG:CIPHERTEXT format.");
            return null;
        }
        const [iv, tag, ciphertext] = parts;

        const masterKey = Buffer.from(process.env.API_MASTER_KEY_BASE64, "base64");
        const decipher = crypto.createDecipheriv(
            "aes-256-gcm",
            masterKey,
            Buffer.from(iv, encoding)
        );
        decipher.setAuthTag(Buffer.from(tag, encoding));
        const dec = decipher.update(ciphertext, encoding, "utf8");
        return dec + decipher.final("utf8");
    } catch (err) {
        console.error("❌ Decryption failed:", err.message);
        return null;
    }
}

/* -------------------- APPLY ROUTE -------------------- */
app.post('/apply', async (req, res) => {
    try {
        const { role, roblox, discord, email, age, why, experience } = req.body;
        if (!role || !roblox || !discord || !email || !age || !why) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const mailOptions = {
            from: '"Keylo Recruitment" <recruitment@keyloroblox.xyz>',
            to: 'recruitment@keyloroblox.xyz',
            subject: `Application for ${role}`,
            html: `
                <h2>New Application for ${role}</h2>
                <p><strong>Roblox Username:</strong> ${roblox}</p>
                <p><strong>Discord Username:</strong> ${discord}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Age:</strong> ${age}</p>
                <p><strong>Why they want to work here:</strong> ${why}</p>
                <p><strong>Previous experience / portfolio:</strong> ${experience || 'N/A'}</p>
            `,
        };

        await recruitmentTransporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Error sending recruitment email:', err);
        res.status(500).json({ error: 'Failed to send application' });
    }
});

/* -------------------- BASIC ROUTES -------------------- */
app.get('/', (req, res) => {
    res.render('index', { title: 'Keylo' });
});

app.get('/terms', (req, res) => {
    res.render('terms', { title: "Keylo | Terms" });
});

app.get('/register', (req, res) => {
  const pending = req.session.pendingRoblox;

  if (req.query.oauth === 'success' && pending) {
    const { robloxUsername, avatarUrl } = pending;

    // Use the avatar from OAuth, or fallback to a default
    const avatar = avatarUrl || '/assets/default-avatar.png';

    return res.render('passwordregister', {
      title: 'Keylo - Complete Registration',
      csrfToken: req.csrfToken(),
      robloxUsername,
      avatarUrl: avatar
    });
  }

  // Default registration page for new users
  res.render('register', { 
    title: 'Keylo - Register', 
    csrfToken: req.csrfToken() 
  });
});

app.get('/login', (req, res) => {
  const oauthSuccess = req.query.oauth === 'success';
  const username = req.query.username || '';
  const id = req.query.id || '';

  res.render('login', {
    csrfToken: req.csrfToken(),
    oauthSuccess,     // always defined
    robloxUsername: username,
    robloxId: id
  });
});

/* -------------------- SUPPORT PAGE -------------------- */
app.get('/support', (req, res) => {
    res.render('support', { csrfToken: req.csrfToken() });
});

/* -------------------- REGISTER -------------------- */
app.post('/api/register', async (req, res) => {
    try {
        const { robloxUsername, password } = req.body;
        if (!robloxUsername || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // 1️⃣ Lookup Roblox user
        const lookupRes = await axios.post(
            'https://users.roblox.com/v1/usernames/users',
            { usernames: [robloxUsername], excludeBannedUsers: false },
            { headers: { 'Content-Type': 'application/json' } }
        );
        if (!lookupRes.data?.data?.length) {
            return res.status(404).json({ error: 'Roblox user not found' });
        }

        const robloxId = lookupRes.data.data[0].id;

        // 2️⃣ Check if user is banned
        const { data: bannedUsers, error: banError } = await supabaseAccounts
            .from('AccountsBan')
            .select('*')
            .eq('username', robloxUsername);

        if (banError) {
            console.error('❌ Supabase ban check error:', banError);
            return res.status(500).json({ error: 'Error checking ban list' });
        }

        if (bannedUsers?.length) {
            // User is banned, redirect to banned page with reason
            const reason = bannedUsers[0].reason || 'No reason provided';
            return res.render('banned', { username: robloxUsername, reason });
        }

        // 3️⃣ Hash password and insert account
        const hashedPassword = await bcrypt.hash(password, 12);
        const { error } = await supabaseAccounts
            .from('Accounts')
            .insert([{ 'roblox username': robloxUsername, 'hashed password': hashedPassword }]);

        if (error) {
            console.error('❌ Supabase Accounts insert error:', error);
            return res.status(500).json({ error: 'Database insert failed' });
        }

        // 4️⃣ Get avatar URL and set cookies
        const avatarUrl = await getAvatarUrl(robloxId);
        setUserCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl, theme: 'n/a' });

        // 5️⃣ Redirect to launch
        res.redirect('/launch');

    } catch (err) {
        console.error('❌ Registration error:', err);
        res.status(500).send('Server error during registration');
    }
});


/* -------------------- LOGIN -------------------- */
app.post('/login', async (req, res) => {
    try {
        const { robloxUsername, password } = req.body;
        if (!robloxUsername || !password) {
            return res.status(400).json({ error: 'Missing credentials' });
        }

        // 1️⃣ Fetch user from Accounts table
        const { data: users, error } = await supabaseAccounts
            .from('Accounts')
            .select('*')
            .eq('roblox username', robloxUsername)
            .limit(1);

        if (error) {
            console.error('❌ Supabase query error:', error);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!users || users.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        const user = users[0];

        // 2️⃣ Check password
        const match = await bcrypt.compare(password, user['hashed password']);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        // 3️⃣ Check if user is banned
        const { data: bannedUsers, error: banError } = await supabaseAccounts
            .from('AccountsBan')
            .select('*')
            .eq('username', robloxUsername);

        if (banError) {
            console.error('❌ Supabase ban check error:', banError);
            return res.status(500).json({ error: 'Error checking ban list' });
        }

        if (bannedUsers?.length) {
            const reason = bannedUsers[0].reason || 'No reason provided';
            return res.render('banned', { username: robloxUsername, reason });
        }

        // 4️⃣ Get Roblox ID and avatar
        const lookupRes = await axios.post(
            'https://users.roblox.com/v1/usernames/users',
            { usernames: [user['roblox username']], excludeBannedUsers: false },
            { headers: { 'Content-Type': 'application/json' } }
        );
        const robloxId = lookupRes.data?.data?.[0]?.id;

        const avatarUrl = await getAvatarUrl(robloxId);
        setUserCookies(res, { id: robloxId, username: user['roblox username'], avatar: avatarUrl, theme: 'n/a' });

        // 5️⃣ Redirect to launch
        res.redirect('/launch');

    } catch (err) {
        console.error('❌ Login error:', err);
        res.status(500).send('Server error during login');
    }
});


/* -------------------- LAUNCH -------------------- */
app.get('/launch', (req, res) => {
    if (!req.cookies.user_id) return res.redirect('/login');
    res.render('launch', {
        user: req.cookies.username || 'Guest',
        userProfileURL: req.cookies.profile_pic || '/images/default-avatar.png',
        csrfToken: req.csrfToken(),
    });
});

/* -------------------- LOGOUT -------------------- */
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.clearCookie('user_id');
        res.clearCookie('username');
        res.clearCookie('profile_pic');
        res.clearCookie('theme');
        res.redirect('/login');
    });
});

/* -------------------- ROBLOX HELPERS -------------------- */
const EMOJIS = ['😀', '🎮', '🌟', '🚀', '🐱', '🔥', '🎲', '💎', '🛡️', '⚔️'];
function generateEmojiCode(len = 5) {
    return Array.from({ length: len }, () => EMOJIS[Math.floor(Math.random() * EMOJIS.length)]).join('');
}
app.get('/api/roblox/user/:id', async (req, res, next) => {
    try {
        const { id } = req.params;
        const profileRes = await axios.get(`https://users.roblox.com/v1/users/${id}`);
        const profile = profileRes.data;
        const avatarUrl = await getAvatarUrl(id);

        res.json({
            id: profile.id,
            name: profile.name,
            avatar: avatarUrl
        });
    } catch (err) {
        console.error('❌ Roblox user lookup error:', err.message);
        next(err);
    }
});

app.get('/api/register/get/robloxusername/:id', async (req, res, next) => {
    try {
        const { id } = req.params;
        const name = await fetchRobloxUsernameById(id);
        res.json({ success: true, username: name });
    } catch (err) {
        next(err);
    }
});

app.get('/api/roblox/code', (req, res) => {
    const code = generateEmojiCode();
    req.session.verificationCode = code;
    req.session.codeGeneratedAt = Date.now();
    res.json({ code });
});

app.get('/api/roblox/check-bio/:id/:code', async (req, res, next) => {
    try {
        const { id, code } = req.params;

        if (!req.session.verificationCode || Date.now() - req.session.codeGeneratedAt > 5 * 60 * 1000) {
            throw new Error('Code expired');
        }
        if (req.session.verificationCode !== code) {
            throw new Error('Invalid code');
        }

        const profileRes = await axios.get(`https://users.roblox.com/v1/users/${id}`);
        const profile = profileRes.data;
        const avatarUrl = await getAvatarUrl(id);

        if (profile.description && profile.description.includes(code)) {
            res.json({ success: true, id, name: profile.name, avatar: avatarUrl });
        } else {
            throw new Error('Code not found in bio');
        }
    } catch (err) {
        next(err);
    }
});

/* -------------------- WORKSPACES ROUTES -------------------- */

/* -------------------- API KEY GENERATION ENDPOINT -------------------- */
app.post('/workspace/:id/generate-api-key', async (req, res) => {
    try {
        if (!req.cookies.user_id) return res.status(401).json({ error: "Unauthorized" });

        const workspaceId = req.params.id;

        // 1. Generate new key and encrypt (returns IV:TAG:CIPHERTEXT)
        const newPlainKey = generateApiKey(48); 
        const combinedEncryptedKey = encryptApiKey(newPlainKey);

        if (!combinedEncryptedKey) {
            return res.status(500).json({ error: "Failed to encrypt API key." });
        }
        
        // 2. Update the workspace record, storing the combined string in API_Key
        const { error } = await supabaseWorkspaces
            .from("existing workspaces")
            .update({
                API_Key: combinedEncryptedKey, 
                // Clear old legacy fields just in case
                api_key: null,
                api_key_encrypted: null,
                api_iv: null,
                api_tag: null, 
            })
            .eq("id", workspaceId);

        if (error) {
            console.error("❌ Supabase update error during key generation:", error);
            return res.status(500).json({ error: 'Database update failed.' });
        }

        res.redirect(`/workspace/${workspaceId}/settings`); 

    } catch (err) {
        console.error("❌ Unhandled error generating API key:", err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/workspace/:id/regenerate-api-key', async (req, res) => {
  try {
    if (!req.cookies.user_id) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const workspaceId = req.params.id;
    if (!workspaceId) {
      return res.status(400).json({ error: "Invalid workspace ID" });
    }

    const newPlainKey = generateApiKey(48);
    const combinedEncryptedKey = encryptApiKey(newPlainKey);

    if (!combinedEncryptedKey) {
      return res.status(500).json({ error: "Failed to encrypt API key." });
    }

    const { error } = await supabaseWorkspaces
      .from("existing workspaces")
        .update({
            API_Key: combinedEncryptedKey
        })

      .eq("id", workspaceId);

    if (error) {
      console.error("❌ Supabase update error:", error);
      return res.status(500).json({ error: "Database update failed." });
    }

    console.log(`✅ Regenerated API key for workspace ${workspaceId}`);

    // ✅ Redirect back to settings page
    return res.redirect(`/workspace/${workspaceId}/settings`);

  } catch (err) {
    console.error("❌ Unhandled error during API key regeneration:", err);
    return res.status(500).json({ error: "Server error regenerating API key." });
  }
});

app.get('/workspace/:id', async (req, res) => {
    try {
        if (!req.cookies.user_id) {
            return res.redirect('/login');
        }

        const workspaceId = req.params.id;

        // fetch workspace from Supabase
        const { data: ws, error } = await supabaseWorkspaces
            .from('existing workspaces')
            .select('*')
            .eq('id', workspaceId)
            .single();

        if (error || !ws) {
            console.error('❌ Workspace not found:', error);
            return res.status(404).send('Workspace not found');
        }

        const robloxId = req.cookies.user_id;
        const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
        const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));

        // check group rank requirement
        if (ws.rblx_group_id && ws.min_rank_id) {
            try {
                const rankRes = await axios.get(
                    `https://groups.roblox.com/v2/users/${robloxId}/groups/roles`
                );
                const groupInfo = rankRes.data?.data?.find(
                    (g) => g.group.id == ws.rblx_group_id
                );
                if (!groupInfo || groupInfo.role.rank < parseInt(ws.min_rank_id, 10)) {
                    // ❌ not allowed – render fun animation + redirect
                    return res.render('notallowed', {
                        user: username,
                        userProfileURL: avatarUrl,
                        redirectUrl: '/workspaces',
                        csrfToken: req.csrfToken(),
                    });
                }
            } catch (err) {
                console.error('❌ Error checking Roblox group rank:', err.message);
                return res.render('notallowed', {
                    user: username,
                    userProfileURL: avatarUrl,
                    redirectUrl: '/workspaces',
                    csrfToken: req.csrfToken(),
                });
            }
        }

        // ✅ allowed – render workspace home
        res.render('workspacehome', {
            user: username,
            userProfileURL: avatarUrl,
            workspace: {
                id: ws.id,
                name: ws.workspace_name,
                image: ws.workspace_img_url,
            },
            csrfToken: req.csrfToken(),
        });
    } catch (err) {
        console.error('❌ Error loading workspace:', err);
        res.status(500).send('Server error');
    }
});


// Workspaces list (with optional group rank filter as in old code)
// make it so say if user a gets given a link by user b on /workspace/id it checks thier group rank from settings table before lettign them in, if not show some cool animation of not allowed blaa blaa redirect in 10 seconds to /wroksapces, if they are then let them in
app.get('/workspaces', async (req, res) => {
    try {
        if (!req.cookies.user_id) {
            return res.redirect('/login');
        }

        const robloxId = req.cookies.user_id;
        const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
        const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));

        const { data: workspaces, error } = await supabaseWorkspaces
            .from('existing workspaces')
            .select('*');

        if (error) {
            console.error('❌ Supabase Workspaces fetch error:', error);
            return res.render('workspaces', {
                user: username,
                userProfileURL: avatarUrl,
                csrfToken: req.csrfToken(),
                workspaces: [],
            });
        }

        const allowedWorkspaces = [];
        for (let ws of workspaces) {
            if (!ws.rblx_group_id || !ws.min_rank_id) {
                allowedWorkspaces.push(ws);
                continue;
            }
            try {
                const rankRes = await axios.get(
                    `https://groups.roblox.com/v2/users/${robloxId}/groups/roles`
                );
                const groupInfo = rankRes.data?.data?.find((g) => g.group.id == ws.rblx_group_id);
                if (groupInfo && groupInfo.role.rank >= parseInt(ws.min_rank_id, 10)) {
                    allowedWorkspaces.push(ws);
                }
            } catch (err) {
                console.warn(`⚠️ Could not check group rank for ws ${ws.id}: ${err.message}`);
            }
        }

        res.render('workspaces', {
            user: username,
            userProfileURL: avatarUrl,
            csrfToken: req.csrfToken(),
            workspaces: allowedWorkspaces.map((ws) => ({
                id: ws.id,
                name: ws.workspace_name,
                image: ws.workspace_img_url,
            })),
        });
    } catch (err) {
        console.error('❌ Workspaces load error:', err);
        res.render('workspaces', {
            user: 'Guest',
            userProfileURL: '/images/default-avatar.png',
            csrfToken: req.csrfToken(),
            workspaces: [],
        });
    }
});

// Create workspace

async function generateUniqueWorkspaceId() {
    let id;
    let exists = true;

    while (exists) {
        id = Math.floor(Math.random() * 1000000); // e.g., 6-digit random number
        const { data, error } = await supabaseWorkspaces
            .from('existing workspaces')
            .select('id')
            .eq('id', id)
            .limit(1);

        if (error) {
            throw new Error('Error checking workspace ID uniqueness: ' + error.message);
        }

        exists = data.length > 0;
    }

    return id;
}

/* -------------------- WORKSPACE CREATION (FIXED FOR ENCRYPTION) -------------------- */
app.post('/workspace/create', async (req, res) => {
    try {
        if (!req.cookies.user_id)
            return res.status(401).json({ error: 'Not logged in' });

        const { name, image, groupId, minRank } = req.body;
        if (!name || !image || !groupId || !minRank)
            return res.status(400).json({ error: 'Missing required fields' });

        const ownerUsername =
            req.cookies.username ||
            (await fetchRobloxUsernameById(req.cookies.user_id));
        const newWorkspaceId = await generateUniqueWorkspaceId();

        // --- generate API key and encrypt it ---
        // 1. Generate the plaintext key
        const apiKeyPlain = generateApiKey(48); // Using the new function signature
        
        // 2. Encrypt and combine (IV:TAG:CIPHERTEXT)
        const combinedEncryptedKey = encryptApiKey(apiKeyPlain);

        if (!combinedEncryptedKey) {
            console.error('❌ API Key encryption failed during creation.');
            return res.status(500).json({ success: false, error: 'Failed to encrypt API key' });
        }
        // --- end API key generation ---

        const { error } = await supabaseWorkspaces
            .from('existing workspaces')
            .insert([
                {
                    workspace_name: name,
                    id: newWorkspaceId,
                    owner_username: ownerUsername,
                    workspace_img_url: image,
                    rblx_group_id: groupId,
                    min_rank_id: minRank,
                    // Store the combined encrypted string
                    API_Key: combinedEncryptedKey, 
                },
            ]);

        if (error) {
            console.error('❌ Supabase insert error:', error);
            return res.json({ success: false, error: 'Database insert failed' });
        }

        const sessionsTableName = `ws_sessions_${newWorkspaceId}`;
        const activityTableName = `ws_activity_${newWorkspaceId}`;
        const tasksTableName = `ws_tasks_${newWorkspaceId}`;
        const logbookTableName = `ws_logbook_${newWorkspaceId}`;
        const settingsTableName = `ws_settings_${newWorkspaceId}`;

        try {
            // NOTE: SQL CREATE statements are unchanged as they define schema, not data values.
            const createSessionsTableQuery = `
                CREATE TABLE IF NOT EXISTS ${sessionsTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    host_id BIGINT NOT NULL,
                    co_host_id BIGINT,
                    start_time TIMESTAMPTZ NOT NULL,
                    duration_minutes INTEGER,
                    groups JSONB,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createActivityTableQuery = `
                CREATE TABLE IF NOT EXISTS ${activityTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id BIGINT NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    tracked_time INTEGER NOT NULL,
                    chats INTEGER NOT NULL,
                    session_id UUID REFERENCES ${sessionsTableName}(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createTasksTableQuery = `
                CREATE TABLE IF NOT EXISTS ${tasksTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    assigned_to BIGINT,
                    completed BOOLEAN DEFAULT FALSE,
                    assigned_by VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createLogbookTableQuery = `
                CREATE TABLE IF NOT EXISTS ${logbookTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    author BIGINT NOT NULL,
                    target_user_id BIGINT NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    expiry_date TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createSettingsTableQuery = `
                CREATE TABLE IF NOT EXISTS ${settingsTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    min_role_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    api_key TEXT NOT NULL,
                    worksapce_name TEXT NOT NULL,
                    features_sessions BOOLEAN DEFAULT FALSE,
                    features_logbook BOOLEAN DEFAULT FALSE,
                    features_auditlogs BOOLEAN DEFAULT TRUE,
                    features_activity BOOLEAN DEFAULT TRUE,
                    features_documents BOOLEAN DEFAULT FALSE,
                    roles JSONB,
                    logs JSONB,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;

            await pgClient.query(createSessionsTableQuery);
            await pgClient.query(createActivityTableQuery);
            await pgClient.query(createTasksTableQuery);
            await pgClient.query(createLogbookTableQuery);
            await pgClient.query(createSettingsTableQuery);

            console.log(`✅ All tables for new workspace '${newWorkspaceId}' created successfully.`);
        } catch (dbErr) {
            console.error(`❌ Error creating tables for workspace '${newWorkspaceId}':`, dbErr);
            return res.json({ success: false, error: 'Database table creation failed' });
        }

        // Return the PLAINTEXT key to the user only once
        res.json({
            success: true,
            workspaceId: newWorkspaceId,
            apiKey: apiKeyPlain, 
        });
    } catch (err) {
        console.error('❌ Workspace create error:', err);
        res.json({ success: false, error: 'Server error' });
    }
});

/* -------------------- SESSIONS PAGE (REAL DATA) -------------------- */
app.get('/workspace/:id/sessions', async (req, res) => {
    try {
        // CSRF tokens are typically for POST requests, but this block
        // handles the specific case where the CSRF middleware is
        // incorrectly checking GET requests, leading to a 403 error.
        req.csrfToken();

        if (!req.cookies.user_id) {
            console.warn('⚠️ No user ID cookie found. Redirecting to login.');
            return res.redirect('/login');
        }

        const workspaceId = req.params.id;

        // --- Step 1: Fetch workspace data from Supabase ---
        let ws;
        try {
            const { data, error } = await supabaseWorkspaces
                .from('existing workspaces')
                .select('*')
                .eq('id', workspaceId)
                .single();

            if (error || !data) {
                console.error('❌ Supabase error: Workspace not found for ID:', workspaceId, 'Error:', error);
                return res.status(404).send('Workspace not found');
            }
            ws = data;
        } catch (err) {
            console.error('❌ Error fetching workspace from Supabase:', err);
            return res.status(500).send('Database error');
        }

        const robloxId = req.cookies.user_id;

        // --- Step 2: Fetch user details from external APIs ---
        let username = req.cookies.username;
        let avatarUrl = req.cookies.profile_pic;

        try {
            if (!username) {
                username = await fetchRobloxUsernameById(robloxId);
            }
            if (!avatarUrl) {
                avatarUrl = await getAvatarUrl(robloxId);
            }
        } catch (err) {
            console.error('❌ Error fetching Roblox user details:', err);
            // Continue with default values if API calls fail
            username = username || 'Unknown User';
            avatarUrl = avatarUrl || 'https://placehold.co/150x150';
        }

        // --- Step 3: Query today's sessions from PostgreSQL ---
        let sessions = [];
        try {
            const todayIndex = new Date().getDay();
            const targetDate = getClosestDateForWeekday(todayIndex);
            const tableName = `ws_sessions_${workspaceId}`;
            const query = `
                SELECT * FROM "${tableName}"
                WHERE DATE(start_time) = $1
                ORDER BY start_time ASC
            `;
            const { rows } = await pgClient.query(query, [targetDate]);
            sessions = rows;
        } catch (err) {
            console.error('❌ Error querying sessions from PostgreSQL:', err);
            // Continue with an empty sessions array if the query fails
            sessions = [];
        }

        // --- Step 4: Build weekday buttons for the view ---
        const days = [
            { label: 'Sun', index: 0, active: new Date().getDay() === 0 },
            { label: 'Mon', index: 1, active: new Date().getDay() === 1 },
            { label: 'Tue', index: 2, active: new Date().getDay() === 2 },
            { label: 'Wed', index: 3, active: new Date().getDay() === 3 },
            { label: 'Thu', index: 4, active: new Date().getDay() === 4 },
            { label: 'Fri', index: 5, active: new Date().getDay() === 5 },
            { label: 'Sat', index: 6, active: new Date().getDay() === 6 },
        ];

        // --- Step 5: Render the page with the gathered data ---
        res.render('sessions', {
            user: username,
            userProfileURL: avatarUrl,
            workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url },
            sessions,
            days,
            csrfToken: req.csrfToken(), // Make sure this is called before rendering
        });
    } catch (err) {
        // Specific error handling for CSRF issues.
        if (err.code === 'EBADCSRFTOKEN') {
            console.error('❌ Forbidden: Invalid CSRF token. The middleware might be misconfigured on this GET route.');
            // This is a common pattern to handle this specific error.
            return res.redirect('/login');
        }
        
        // General server error fallback.
        console.error('❌ Unhandled error loading sessions:', err);
        res.status(500).send('Server error');
    }
});

/* -------------------- WORKSPACE SETTINGS -------------------- */
app.get("/workspace/:id/settings", async (req, res) => {
    try {
        if (!req.cookies.user_id) return res.redirect("/login");

        const workspaceId = req.params.id;
        const { data: ws, error } = await supabaseWorkspaces
            .from("existing workspaces")
            .select("*")
            .eq("id", workspaceId)
            .single();

        if (error || !ws) return res.status(404).send("Workspace not found");

        let decryptedKey = null;

        // ✅ Attempt to decrypt the combined key from the API_Key column
        if (ws.API_Key) {
            decryptedKey = decryptApiKey(ws.API_Key);
            if (!decryptedKey) {
                console.warn('⚠️ Could not decrypt key from API_Key column. It may be corrupt or unencrypted.');
            }
        } 
        
        // Fallback for unencrypted legacy key (if you still have one)
        if (!decryptedKey && ws.api_key) {
            decryptedKey = ws.api_key;
        }

        // Fetch user info
        const robloxId = req.cookies.user_id;
        let username = req.cookies.username;
        let avatarUrl = req.cookies.profile_pic;

        try {
            if (!username) username = await fetchRobloxUsernameById(robloxId);
            if (!avatarUrl) avatarUrl = await getAvatarUrl(robloxId);
        } catch (err) {
            console.error('❌ Error fetching Roblox user details:', err);
            username = username || 'Unknown User';
            avatarUrl = avatarUrl || 'https://placehold.co/150x150';
        }

        res.render("workspacesettings", {
            user: username,
            userProfileURL: avatarUrl,
            workspace: {
                id: ws.id,
                name: ws.workspace_name,
                image: ws.workspace_img_url,
            },
            csrfToken: req.csrfToken(),
            apiKeyDecrypted: decryptedKey, // ✅ Pass decrypted key to EJS
        });
    } catch (err) {
        console.error("❌ Error loading settings:", err);
        res.status(500).send("Server error");
    }
});

/* -------------------- WORKSPACE ACTIVITY -------------------- */
app.get('/workspace/:id/activity', async (req, res) => {
    try {
        // NOTE: Call req.csrfToken() once and before rendering/redirecting
        const csrfToken = req.csrfToken(); 

        // --- Check login ---
        if (!req.cookies.user_id) {
            console.warn('⚠️ No user ID cookie found. Redirecting to login.');
            return res.redirect('/login');
        }

        const workspaceId = req.params.id;
        const robloxId = req.cookies.user_id;

        // --- Step 1: Fetch workspace data from Supabase ---
        let ws;
        try {
            const { data, error } = await supabaseWorkspaces
                .from('existing workspaces')
                .select('*')
                .eq('id', workspaceId)
                .single();

            if (error || !data) {
                console.error('❌ Workspace not found for ID:', workspaceId, 'Error:', error);
                return res.status(404).send('Workspace not found');
            }
            ws = data;
        } catch (err) {
            console.error('❌ Error fetching workspace from Supabase:', err);
            return res.status(500).send('Database error');
        }

        // --- Step 2: Get Roblox user info ---
        let username = req.cookies.username;
        let avatarUrl = req.cookies.profile_pic;
        try {
            if (!username) username = await fetchRobloxUsernameById(robloxId);
            if (!avatarUrl) avatarUrl = await getAvatarUrl(robloxId);
        } catch (err) {
            console.error('❌ Error fetching Roblox user details:', err);
            username = username || 'Unknown User';
            avatarUrl = avatarUrl || 'https://placehold.co/150x150';
        }

        // --- Step 3: Load player activity (FIXED SQL QUERY) ---
        const tableName = `ws_activity_${workspaceId}`;
        let activityRows = [];
        try {
            // Explicitly select columns and use AS to map to the expected names
            const { rows } = await pgClient.query(
                `SELECT 
                    tracked_time,
                    chats, 
                    type AS activity_type, 
                    created_at AS timestamp, 
                    '' AS description  
                 FROM "${tableName}" 
                 WHERE user_id = $1 
                 ORDER BY created_at DESC`, 
                [robloxId]
            );
            activityRows = rows;
        } catch (err) {
            console.error('❌ Error fetching activity from table', tableName, err);
            activityRows = []; 
        }

        // --- Step 4: Compute stats (DAILY AVERAGE CALCULATION CHANGED HERE) ---
        let todaysTime = 0;
        let totalTime = 0;
        let todaysChats = 0;
        const todayDate = new Date().toISOString().slice(0, 10); 

        // Retaining dayTotals for future use, though not needed for the new average calculation
        const dayTotals = {}; 

        activityRows.forEach(a => {
            const date = new Date(a.timestamp).toISOString().slice(0, 10);
            const trackedTime = a.tracked_time || 0;
            totalTime += trackedTime;
            dayTotals[date] = (dayTotals[date] || 0) + trackedTime;

            if (date === todayDate) {
                todaysTime += trackedTime;
                todaysChats += a.chats || 0;
            }
        });

        // 💡 UPDATED CALCULATION: Total time divided by the total number of entries/rows
        const dailyAverage =
            activityRows.length > 0
                ? Math.round(totalTime / activityRows.length) // Changed Object.keys(dayTotals).length to activityRows.length
                : 0;

        // --- Step 5: Prepare recent activity list ---
        const activity = activityRows.map(a => ({
            user: username,
            description: a.activity_type === 'chat' 
                ? `Sent ${a.chats} messages.` 
                : `Active for ${a.tracked_time} mins. Type: ${a.activity_type}`,
            time: new Date(a.timestamp).toLocaleString(),
            type: a.activity_type || 'other',
        }));

        // --- Step 6: Render EJS page ---
        res.render('activity', {
            user: username,
            userProfileURL: avatarUrl,
            workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url },
            todaysTime,
            dailyAverage, // This is now the average time per entry
            totalTime,
            todaysChats,
            activity,
            csrfToken,
        });

    } catch (err) {
        if (err.code === 'EBADCSRFTOKEN') {
            console.error('❌ Forbidden: Invalid CSRF token on GET /activity.');
            return res.redirect('/login');
        }

        console.error('❌ Unhandled error loading activity:', err);
        res.status(500).send('Server error');
    }
});

// route: get sessions for a given workspace + weekday
app.get('/api/workspace/:id/sessions/day/:dayIndex', async (req, res) => {
    const { id, dayIndex } = req.params;
    const dayIdx = parseInt(dayIndex, 10);
    const workspaceId = parseInt(id, 10);
    if (isNaN(dayIdx) || isNaN(workspaceId) || dayIdx < 0 || dayIdx > 6) {
        return res.status(400).json({ error: 'Invalid parameters' });
    }
    const dateStr = getClosestDateForWeekday(dayIdx);
    const tableName = `ws_sessions_${workspaceId}`;
    try {
        const query = `
            SELECT * FROM "${tableName}"
            WHERE DATE(start_time) = $1
            ORDER BY start_time ASC
        `;
        const { rows } = await pgClient.query(query, [dateStr]);
        const sessions = rows.map(row => ({
            id: row.id,
            title: row.title,
            timeFormatted: row.start_time ? new Date(row.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
            isLive: false,
            type: row.type,
            host: {
                name: row.host_name || 'Unknown',
                avatar: row.host_avatar || '/icons/icons8-avatar-24.png',
            }
        }));
        res.json({ sessions });
    } catch (err) {
        console.error('Error fetching sessions by day:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/* -------------------- ERROR HANDLER -------------------- */
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (req.accepts('json')) {
        return res.status(500).json({ error: err.message || 'Server error' });
    }
    res.status(500).send('Server error');
});

/* -------------------- MISC -------------------- */
/* Workspace dedicated endpoint for creation for sessions */
app.post('/api/sessions/:workspaceId/entry/new', async (req, res) => {
    try {
        const workspaceId = req.params.workspaceId;
        let { title, type, hostId, coHostId, startTime, durationMinutes, groups } = req.body;

        // Validate required fields
        if (!title || !type || !startTime || !durationMinutes || !hostId) {
            return res.status(400).json({ error: 'Missing required fields (title, type, startTime, durationMinutes, hostId)' });
        }

        // Convert numbers
        durationMinutes = Number(durationMinutes);
        hostId = Number(hostId);
        coHostId = coHostId ? Number(coHostId) : null;

        if (isNaN(durationMinutes) || durationMinutes < 1) {
            return res.status(400).json({ error: 'durationMinutes must be a positive number' });
        }
        if (isNaN(hostId) || hostId < 1) {
            return res.status(400).json({ error: 'hostId must be a positive number' });
        }
        if (coHostId !== null && (isNaN(coHostId) || coHostId < 1)) {
            return res.status(400).json({ error: 'coHostId must be a positive number or null' });
        }

        // Convert startTime to ISO string
        const startTimeISO = new Date(startTime).toISOString();
        if (isNaN(new Date(startTimeISO))) {
            return res.status(400).json({ error: 'Invalid startTime format' });
        }

        const createdAt = new Date().toISOString();
        const tableName = `ws_sessions_${workspaceId}`; // workspace-specific table

        const pgQuery = `
            INSERT INTO "${tableName}" 
            (title, type, host_id, co_host_id, start_time, duration_minutes, groups, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
        `;
        const pgValues = [title, type, hostId, coHostId, startTimeISO, durationMinutes, groups || [], createdAt];

        const { rows } = await pgClient.query(pgQuery, pgValues);

        res.status(201).json({ message: 'Session created successfully', session: rows[0] });

    } catch (err) {
        console.error('❌ Error creating session:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

async function getStaffAvatarUrls(staffMembers) {
    if (!staffMembers || staffMembers.length === 0) return [];

    const avatarMap = {};
    const batchSize = 100;
    const batches = [];

    const validMembers = staffMembers.filter(m =>
        m && m.id && !isNaN(Number(m.id))
    );

    for (let i = 0; i < validMembers.length; i += batchSize) {
        batches.push(validMembers.slice(i, i + batchSize));
    }

    try {
        for (const batch of batches) {
            const userIds = batch.map(m => m.id).join(',');
            console.log("🟢 Fetching Roblox avatars for:", userIds);

            const apiUrl = `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${encodeURIComponent(userIds)}&size=180x180&format=Png&isCircular=true`;
            const res = await fetch(apiUrl);

            if (!res.ok) {
                console.error(`❌ Roblox API returned ${res.status}: ${res.statusText}`);
                throw new Error(`Roblox Thumbnails API failed: ${res.status}`);
            }

            const data = await res.json();
            data.data.forEach(item => {
                avatarMap[item.targetId] =
                    item.state === "Completed"
                        ? item.imageUrl
                        : 'https://placehold.co/150x150?text=Pending';
            });
        }

        return staffMembers.map(member => ({
            ...member,
            avatarUrl: avatarMap[member.id] || 'https://placehold.co/150x150?text=No+Image'
        }));

    } catch (err) {
        console.error('❌ Error fetching Roblox avatars:', err);
        return staffMembers.map(member => ({
            ...member,
            avatarUrl: 'https://placehold.co/150x150?text=Error'
        }));
    }
}

app.get('/workspace/:id/staff', async (req, res) => {
    try {
        // NOTE: Call req.csrfToken() once and before rendering/redirecting
        const csrfToken = req.csrfToken();

        if (!req.cookies.user_id) {
            console.warn('⚠️ No user ID cookie found. Redirecting to login.');
            return res.redirect('/login');
        }

        const workspaceId = req.params.id;
        const robloxId = req.cookies.user_id;

        // --- Step 1: Fetch workspace data from Supabase ---
        let ws;
        try {
            const { data, error } = await supabaseWorkspaces
                .from('existing workspaces')
                .select('*')
                .eq('id', workspaceId)
                .single();

            if (error || !data) {
                console.error('❌ Supabase error: Workspace not found for ID:', workspaceId, 'Error:', error);
                return res.status(404).send('Workspace not found');
            }
            ws = data;
        } catch (err) {
            console.error('❌ Error fetching workspace from Supabase:', err);
            return res.status(500).send('Database error');
        }

        // --- Step 2: Fetch Roblox user info (for header display) ---
        let username = req.cookies.username;
        let avatarUrl = req.cookies.profile_pic;

        try {
            if (!username) {
                username = await fetchRobloxUsernameById(robloxId);
            }
            if (!avatarUrl) {
                // Ensure getAvatarUrl is used here for the current user's profile picture
                avatarUrl = await getAvatarUrl(robloxId); 
            }
        } catch (err) {
            console.error('❌ Error fetching Roblox user info:', err);
            username = username || 'Unknown User';
            avatarUrl = avatarUrl || 'https://placehold.co/150x150';
        }

        // --- Step 3: Fetch staff data from the API server ---
        let staffData = { staff: [] };
        try {
            const apiUrl = `https://api.keyloroblox.xyz/workspace/${workspaceId}/staff`;
            const apiRes = await fetch(apiUrl);
            if (!apiRes.ok) {
                console.error(`❌ API error: ${apiRes.status} ${apiRes.statusText}`);
                throw new Error(`API request failed with ${apiRes.status}`);
            }
            staffData = await apiRes.json();
        } catch (err) {
            console.error('❌ Error fetching staff from API:', err);
        }

        // 🟢 FIX: Fetch all staff avatar URLs on the server-side
        let staffWithAvatars = [];
        if (staffData.staff && staffData.staff.length > 0) {
            // Using the new helper function for batch fetching
            staffWithAvatars = await getStaffAvatarUrls(staffData.staff); 
        }

        // --- Step 4: Render the EJS view ---
        res.render('workspacestaff', {
            user: username,
            userProfileURL: avatarUrl,
            workspace: {
                id: ws.id,
                name: ws.workspace_name,
                image: ws.workspace_img_url,
                rblx_group_id: staffData.rblx_group_id,
                min_rank_id: staffData.min_rank_id
            },
            // Pass the updated staff list with avatar URLs
            staff: staffWithAvatars, 
            csrfToken: csrfToken 
        });

    } catch (err) {
        // CSRF-specific handling
        if (err.code === 'EBADCSRFTOKEN') {
            console.error('❌ Forbidden: Invalid CSRF token on GET /staff route.');
            return res.redirect('/login');
        }

        // General error fallback
        console.error('❌ Unhandled error loading staff page:', err);
        res.status(500).send('Server error');
    }
});

app.get('/:id/settings/worksapcename/update',async (req, res) => {
    const workspaceId = req.params.id;
    let ws;
    try {
        const { data, error } = await supabaseWorkspaces
            .from('exsisting workspaces')
            .select('*')
            .eq('id', workspaceId)
            .single();

       if (error || !data) {
           console.error('❌ Worksapce not found for ID:', workspaceId, 'Error:', error);
           return res.status(404).send('Workspace not found');
       }
        ws = data;
    } catch (err) {
        console.error('❌ Error fetching workspace from Supabase:', err);
        return res.status(500).send('Database error');
    }

    // Make it find the ID of worksapce and update the worksapce name value
});

app.get('/:id/settings/features/update', async (req, res) => {
    const worksapceId = req.params.id;
    let ws;
    try {
        const { data, error } = await supabaseWorkspaces
            .from(`ws_settings_${worksapceId}`)
            .select('*')
            .eq('id', worksapceId)
            .signle();

        if (error || !data) {
            console.error('❌ Workspace not found for ID:', workspaceId, 'Error:', error);
            return res.tatus(404).send('Workspace not found');
        }
          ws = data;
    } catch (err) {
        console.error('❌ Error etchng workspace from Supabase:', err);
        return res.status(500).send('Database error');
    }

    // Make it find the ID of workspace for ws_settings_{worskpaceid} and update the features in json i n table each feature has its own boolean row. features_sessions features_logbook features_auditlogs features_activity features_documents
});

app.get('/:id/settings/visability/update', async (req, res) => {
    const worksapceId = req.params.id;
    let ws;
    try {
        const { data, error } = await supabaseWorkspaces
            .from(`ws_settings_${workspaceId}`)
            .select('*')
            .eq('id', worksapceId)
            .signle();

        if (error || !data) {
            console.error('❌ Workspace not found for ID:', worksapceId, 'Error:', error)
            return res.tatus(404).send('Workspace not found');
        }
          ws = data;
    } catch (err) {
        console.error('❌ Error etchng workspace from Supabase:', err);
        return res.status(500).send('Database error');
    }

    // Make it find the ID of workspace for ws_settings_{worskpaceid} and update the DO TO FINISH HERE IDK DB RN
});

app.get('/workspace/:id/announcements', async (req, res) => {
  try {
    // --- Step 1: CSRF safety check ---
    req.csrfToken();

    // --- Step 2: Check login cookies ---
    if (!req.cookies.user_id) {
      console.warn('⚠️ No user ID cookie found. Redirecting to login.');
      return res.redirect('/login');
    }

    const workspaceId = req.params.id;

    // --- Step 3: Fetch workspace details from Supabase ---
    let ws;
    try {
      const { data, error } = await supabaseWorkspaces
        .from('existing workspaces')
        .select('*')
        .eq('id', workspaceId)
        .single();

      if (error || !data) {
        console.error('❌ Supabase error: Workspace not found for ID:', workspaceId, 'Error:', error);
        return res.status(404).send('Workspace not found');
      }

      ws = data;
    } catch (err) {
      console.error('❌ Error fetching workspace from Supabase:', err);
      return res.status(500).send('Database error');
    }

    const robloxId = req.cookies.user_id;

    // --- Step 4: Fetch Roblox user details ---
    let username = req.cookies.username;
    let avatarUrl = req.cookies.profile_pic;

    try {
      if (!username) {
        username = await fetchRobloxUsernameById(robloxId);
      }
      if (!avatarUrl) {
        avatarUrl = await getAvatarUrl(robloxId);
      }
    } catch (err) {
      console.error('❌ Error fetching Roblox user details:', err);
      username = username || 'Unknown User';
      avatarUrl = avatarUrl || 'https://placehold.co/150x150';
    }

    // --- Step 5: Fake announcements (temporary static data) ---
    const announcements = [
      {
        id: 1,
        title: "🚀 Welcome to Keylo!",
        content: "We’re thrilled to have you onboard. Stay tuned for upcoming workspace features. Please also check your new staff rules.",
        author: "System",
        date: "2025-11-11",
        timeAgo: dayjs("2025-11-11").fromNow(),
        tags: ["Welcome", "Info"],
        attachments: [
          { name: "Keylo Updated Staff Responsibilites", url: "https://docs.google.com/document/d/1r2wvE_rDwwIqHNiIcmz7RTkz93VzYCSC/edit?usp=sharing&ouid=105835574033665853701&rtpof=true&sd=true" }
        ],
        pinned: true,
        likes: 12,
        comments: 3
      },
      {
        id: 2,
        title: "🧩 Chirstmas Break",
        content: "Please note our christmas and new year holidays start at 19th Dec - 2nd Jan.",
        author: "System",
        date: "10-11-2025",
      },
    ];

    // --- Step 6: Render the announcements page ---
    res.render('workspaceannouncements', {
      title: `${ws.workspace_name} - Announcements`,
      user: username,
      userProfileURL: avatarUrl,
      workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url },
      announcements,
      csrfToken: req.csrfToken(),
      isAdmin: ws.min_rank_id
    });
  } catch (err) {
    if (err.code === 'EBADCSRFTOKEN') {
      console.error('❌ Invalid CSRF token detected — redirecting to login.');
      return res.redirect('/login');
    }

    console.error('❌ Unhandled error loading announcements:', err);
    res.status(500).send('Server error');
  }
});


/* -------------------- START SERVER -------------------- */
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});
