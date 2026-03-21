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

// Ensure required env variables exist
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

// PostgreSQL pool
const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });
async function dbQuery(text, params) { return userdataPool.query(text, params); }

// Redis client
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on("error", (err) => console.error("REDIS_ERROR", { message: err.message }));
redisClient.connect();

// Express middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session middleware (fixed domain + sameSite)
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    name: "keylo.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      domain: ".keylogroup.co.uk",
      maxAge: 30 * 24 * 60 * 60 * 1000
    }
  })
);

// CSRF protection
const csrfProtection = csurf({
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
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
  const opts = {
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    httpOnly: false,
    domain: ".keylogroup.co.uk",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000
  };
  res.cookie("id", String(id), opts);
  res.cookie("username", String(username), opts);
  res.cookie("avatar", String(avatar), opts);
}

function clearLoginCookies(res) {
  const opts = {
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    httpOnly: false,
    domain: ".keylogroup.co.uk",
    path: "/"
  };
  ["id", "username", "avatar", "theme"].forEach((c) => res.clearCookie(c, opts));
}

// Routes
app.get("/", (req, res) => res.render("index", { title: "Keylo" }));

// OAuth start
app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.save(() => {
    const url =
      "https://apis.roblox.com/oauth/v1/authorize?" +
      querystring.stringify({
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
    if (!code || !state || state !== req.session.oauthState)
      return res.status(400).send("Invalid OAuth session");

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

    const existing = await dbQuery(
      'SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1',
      [robloxUsername]
    );

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

// Registration
app.get("/register", csrfProtection, (req, res) => {
  const pending = req.session.pendingRoblox;
  if (req.query.oauth === "success" && pending) {
    return res.render("passwordregister", {
      title: "Complete Registration",
      csrfToken: req.csrfToken(),
      robloxUsername: pending.robloxUsername,
      avatarUrl: pending.avatarUrl
    });
  }
  res.render("register", { title: "Register", csrfToken: req.csrfToken() });
});

app.post("/api/register", csrfProtection, async (req, res) => {
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).send("Password too short");
    const hashed = await bcrypt.hash(password, 12);

    await dbQuery(
      'INSERT INTO "Accounts" ("roblox username","hashed password") VALUES ($1,$2)',
      [pending.robloxUsername, hashed]
    );

    req.session.pendingRoblox = null;
    req.session.loggedIn = true;
    res.redirect("https://app.keylogroup.co.uk/");
  } catch (err) {
    res.status(500).send("Registration failed");
  }
});

// Login / Logout
app.get("/logout", (req, res) => {
  clearLoginCookies(res);
  req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => console.log("OAuth Server running on port", PORT));
