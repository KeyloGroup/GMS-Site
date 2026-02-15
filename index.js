const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const crypto = require("crypto");
const axios = require("axios");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const querystring = require("querystring");

require("dotenv").config({ path: "/root/KeyloENV/.env" });

const app = express();
app.set("trust proxy", 1); // required if behind Nginx/Cloudflare
const PORT = 3000;

if (!process.env.PG_URL_USERDATA) process.exit(1);
if (!process.env.ROBLOX_OAUTH_CLIENT_ID) process.exit(1);
if (!process.env.ROBLOX_OAUTH_CLIENT_SECRET) process.exit(1);
if (!process.env.ROBLOX_OAUTH_REDIRECT_URI) process.exit(1);

const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- SESSION ---
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex");

app.use(session({
  name: "keylo.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: true,               // HTTPS only
    httpOnly: true,             // client cannot access
    sameSite: "none",           // required for cross-site subdomain
    domain: ".keyloroblox.xyz", // leading dot allows subdomains
    maxAge: 1000 * 60 * 60 * 24 * 30,
    path: "/"
  }
}));

// --- CSRF ---
const csrfProtection = csurf({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none",
    domain: ".keyloroblox.xyz",
    path: "/"
  }
});

app.use((req, res, next) => {
  if (["/", "/auth/roblox", "/auth/roblox/callback"].includes(req.path)) return next();
  return csrfProtection(req, res, next);
});

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// --- COOKIE HELPERS ---
function setLoginCookies(res, { id, username, avatar }) {
  const base = {
    secure: true,
    sameSite: "none",
    httpOnly: false,
    domain: ".keyloroblox.xyz",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 30
  };
  res.cookie("id", String(id), base);
  res.cookie("username", String(username), base);
  res.cookie("avatar", String(avatar), base);
}

function clearLoginCookies(res) {
  const base = {
    secure: true,
    sameSite: "none",
    httpOnly: false,
    domain: ".keyloroblox.xyz",
    path: "/"
  };
  ["id","username","avatar","theme"].forEach(c => res.clearCookie(c, base));
}

// --- ROUTES ---
app.get("/", (req, res) => {
  return res.render("index", { title: "Keylo" });
});

app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.save(() => {
    const authUrl = `https://apis.roblox.com/oauth/v1/authorize?` + querystring.stringify({
      client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
      response_type: "code",
      redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
      scope: "openid profile",
      state
    });
    return res.redirect(authUrl);
  });
});

app.get("/auth/roblox/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(error_description || error);
    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");
    if (!req.session.oauthState) return res.status(400).send("Session expired");
    if (state !== req.session.oauthState) return res.status(400).send("Invalid OAuth state");

    const tokenRes = await axios.post(
      "https://apis.roblox.com/oauth/v1/token",
      querystring.stringify({
        grant_type: "authorization_code",
        client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
        client_secret: process.env.ROBLOX_OAUTH_CLIENT_SECRET,
        code,
        redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
    });

    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;

    const banned = await userdataPool.query(
      'SELECT * FROM "AccountsBan" WHERE username = $1 LIMIT 1',
      [robloxUsername]
    );
    if (banned.rows.length > 0) {
      return res.redirect(`https://app.keyloroblox.xyz/account/restricted?reason=${encodeURIComponent(banned.rows[0].reason || "Restricted")}`);
    }

    const users = await userdataPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1',
      [robloxUsername]
    );

    clearLoginCookies(res);
    setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });

    if (users.rows.length > 0) {
      req.session.oauthState = null;
      return req.session.save(() => res.redirect("https://app.keyloroblox.xyz/"));
    }

    req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
    return res.redirect("/register?oauth=success");
  } catch (err) {
    console.error(err);
    clearLoginCookies(res);
    return res.status(500).send("OAuth failed");
  }
});

app.get("/register", (req, res) => {
  const pending = req.session.pendingRoblox;
  if (req.query.oauth === "success" && pending) {
    return res.render("passwordregister", {
      title: "Keylo - Complete Registration",
      csrfToken: req.csrfToken(),
      robloxUsername: pending.robloxUsername,
      avatarUrl: pending.avatarUrl
    });
  }
  return res.render("register", { title: "Keylo - Register", csrfToken: req.csrfToken() });
});

app.post("/api/register", async (req, res) => {
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");

    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    await userdataPool.query(
      'INSERT INTO "Accounts" ("roblox username","hashed password") VALUES ($1,$2)',
      [pending.robloxUsername, hashedPassword]
    );

    req.session.pendingRoblox = null;
    return res.redirect("https://app.keyloroblox.xyz/");
  } catch {
    return res.status(500).send("Registration failed");
  }
});

app.listen(PORT, () => {
  console.log(`keyloroblox.xyz running on port ${PORT}`);
});
