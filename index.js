const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { createClient } = require("redis");
const { RedisStore } = require("connect-redis");
const crypto = require("crypto");
const axios = require("axios");
const bcrypt = require("bcrypt");
const querystring = require("querystring");
const { Pool } = require("pg");
const csurf = require("csurf");

require("dotenv").config({ path: "/root/KeyloENV/.env" });

const app = express();
app.set("trust proxy", 1);
const PORT = 3000;

// Validate env
[
  "PG_URL_USERDATA",
  "ROBLOX_OAUTH_CLIENT_ID",
  "ROBLOX_OAUTH_CLIENT_SECRET",
  "ROBLOX_OAUTH_REDIRECT_URI",
  "SESSION_SECRET",
  "REDIS_URL"
].forEach((v) => {
  if (!process.env[v]) {
    console.error("ENV_MISSING", { key: v });
    process.exit(1);
  }
});

// PostgreSQL
const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });
async function dbQuery(text, params) {
  const res = await userdataPool.query(text, params);
  return res;
}

// Redis
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on("error", (err) => console.error("REDIS_ERROR", { message: err.message }));
redisClient.connect();

// Middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    name: "keylo.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "none",
      domain: ".keylogroup.co.uk",
      maxAge: 30 * 24 * 60 * 60 * 1000
    }
  })
);

// CSRF
const csrfProtection = csurf({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none",
    domain: ".keylogroup.co.uk",
    path: "/"
  }
});

// Views
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// Cookie helpers
function setLoginCookies(res, { id, username, avatar }) {
  const opts = { secure: true, sameSite: "none", httpOnly: false, domain: ".keylogroup.co.uk", path: "/", maxAge: 30 * 24 * 60 * 60 * 1000 };
  res.cookie("id", String(id), opts);
  res.cookie("username", String(username), opts);
  res.cookie("avatar", String(avatar), opts);
}

function clearLoginCookies(res) {
  const opts = { secure: true, sameSite: "none", httpOnly: false, domain: ".keylogroup.co.uk", path: "/" };
  ["id", "username", "avatar", "theme"].forEach((c) => res.clearCookie(c, opts));
}

// ---------------- ROUTES ----------------

// Root
app.get("/", (req, res) => {
  res.render("index", { title: "Keylo" });
});

// OAuth start
app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.save(() => {
    const url = "https://apis.roblox.com/oauth/v1/authorize?" + querystring.stringify({
      client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
      response_type: "code",
      redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
      scope: "openid profile",
      state
    });
    res.redirect(url);
  });
});

// OAuth callback
app.get("/auth/roblox/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(error_description || error);
    if (!code || !state || state !== req.session.oauthState) return res.status(400).send("Invalid OAuth session");

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

    // BAN CHECK FIRST
    const banned = await dbQuery('SELECT * FROM "AccountsBan" WHERE username=$1 LIMIT 1', [robloxUsername]);
    if (banned.rows.length > 0) {
      return res.redirect(`https://app.keylogroup.co.uk/account/restricted?reason=${encodeURIComponent(banned.rows[0].reason || "Restricted")}`);
    }

    // EXISTING ACCOUNT CHECK
    const existing = await dbQuery('SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1', [robloxUsername]);

    clearLoginCookies(res);
    setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });
    req.session.oauthState = null;

    if (existing.rows.length > 0) {
      req.session.loggedIn = true;
      return req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
    }

    req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
    res.redirect("/register?oauth=success");
  } catch (err) {
    clearLoginCookies(res);
    res.status(500).send("OAuth failed");
  }
});

// Register page
app.get("/register", csrfProtection, (req, res) => {
  const pending = req.session.pendingRoblox;
  if (req.query.oauth === "success" && pending) {
    return res.render("passwordregister", { csrfToken: req.csrfToken(), robloxUsername: pending.robloxUsername, avatarUrl: pending.avatarUrl });
  }
  res.render("register", { csrfToken: req.csrfToken() });
});

// Register API
app.post("/api/register", csrfProtection, async (req, res) => {
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).send("Password too short");
    const hashed = await bcrypt.hash(password, 12);
    await dbQuery('INSERT INTO "Accounts" ("roblox username","hashed password") VALUES ($1,$2)', [pending.robloxUsername, hashed]);
    req.session.pendingRoblox = null;
    req.session.loggedIn = true;
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    res.status(500).send("Registration failed");
  }
});

// Login page
app.get("/login", csrfProtection, (req, res) => {
  res.render("login", { csrfToken: req.csrfToken() });
});

// Login API
app.post("/login", csrfProtection, async (req, res) => {
  try {
    const { robloxUsername, password } = req.body;
    if (!robloxUsername || !password) return res.status(400).send("Missing credentials");
    const users = await dbQuery('SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1', [robloxUsername]);
    if (!users.rows.length) return res.status(401).send("User not found");
    const match = await bcrypt.compare(password, users.rows[0]["hashed password"]);
    if (!match) return res.status(401).send("Invalid password");
    req.session.loggedIn = true;
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    res.status(500).send("Login failed");
  }
});

// Logout
app.get("/logout", (req, res) => {
  clearLoginCookies(res);
  req.session.destroy(() => res.redirect("/"));
});

// Restricted page
app.get("/account/restricted", (req, res) => {
  res.send(`Account restricted: ${req.query.reason || "No reason provided"}`);
});

// 404
app.use((req, res) => res.status(404).render("404"));

// Error handler
app.use((err, req, res, next) => res.status(500).send("Internal server error"));

app.listen(PORT, () => console.log("SERVER_START", { host: "keylogroup.co.uk", port: PORT }));
