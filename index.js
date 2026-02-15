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

// CRITICAL: Must be at the top for cookies to work behind a proxy
app.set("trust proxy", 1);
const PORT = 3000;

if (!process.env.PG_URL_USERDATA) process.exit(1);
if (!process.env.ROBLOX_OAUTH_CLIENT_ID) process.exit(1);
if (!process.env.ROBLOX_OAUTH_CLIENT_SECRET) process.exit(1);
if (!process.env.ROBLOX_OAUTH_REDIRECT_URI) process.exit(1);

const AccountsPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });
const AccountsBannedPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });

// Middleware Order: Body Parsers -> Cookies -> Session -> CSURF
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex");

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    name: "keylo_sess", // Custom name to avoid conflicts
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "none",
      domain: "keyloroblox.xyz", 
      maxAge: 1000 * 60 * 60 * 24 * 30,
      path: "/",
    },
  })
);

app.use(
  csurf({
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "none",
      domain: "keyloroblox.xyz",
      path: "/",
    },
  })
);

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// --- Helper Functions ---

function clearLoginCookies(res) {
  const base = {
    secure: true,
    sameSite: "none",
    httpOnly: false,
    domain: "keyloroblox.xyz",
    path: "/",
  };

  ["id", "username", "avatar", "theme"].forEach((c) => {
    res.clearCookie(c, base);
  });
}

function setLoginCookies(res, { id, username, avatar }) {
  const base = {
    secure: true,
    sameSite: "none",
    httpOnly: false, // Changed to false so your frontend JS can access if needed
    maxAge: 1000 * 60 * 60 * 24 * 30,
    domain: "keyloroblox.xyz",
    path: "/",
  };

  res.cookie("id", String(id), base);
  res.cookie("username", String(username), base);
  res.cookie("avatar", String(avatar), base);
}

// --- Routes ---

app.get("/", (req, res) => {
  return res.render("index", { title: "Keylo" });
});

app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const authUrl =
    `https://apis.roblox.com/oauth/v1/authorize?` +
    querystring.stringify({
      client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
      response_type: "code",
      redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
      scope: "openid profile",
      state,
    });

  return res.redirect(authUrl);
});

app.get("/auth/roblox/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) return res.status(400).send(error_description || error);
    if (!state || state !== req.session.oauthState) return res.status(400).send("Invalid OAuth state");
    if (!code) return res.status(400).send("Missing code");

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

    const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;

    const banned = await AccountsBannedPool.query(
      'SELECT * FROM "AccountsBan" WHERE username = $1 LIMIT 1',
      [robloxUsername]
    );

    if (banned.rows.length > 0) {
      const ban = banned.rows[0];
      return res.redirect(`https://app.keyloroblox.xyz/account/restricted?reason=${encodeURIComponent(ban.reason || "Restricted")}`);
    }

    const { rows: userRows } = await AccountsPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1',
      [robloxUsername]
    );

    // CRITICAL: Set cookies before redirecting
    clearLoginCookies(res);
    setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });

    if (userRows.length > 0) {
      return res.redirect("https://app.keyloroblox.xyz/");
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
      avatarUrl: pending.avatarUrl,
    });
  }
  return res.render("register", { title: "Keylo - Register", csrfToken: req.csrfToken() });
});

app.post("/api/register", async (req, res) => {
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");

    const { password } = req.body;
    const { robloxUsername, robloxId, avatarUrl } = pending;

    const hashedPassword = await bcrypt.hash(password, 12);
    await AccountsPool.query(
      'INSERT INTO "Accounts" ("roblox username", "hashed password") VALUES ($1, $2)',
      [robloxUsername, hashedPassword]
    );

    setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });
    req.session.pendingRoblox = null;
    return res.redirect("https://app.keyloroblox.xyz/");
  } catch (err) {
    return res.status(500).send("Server error during registration");
  }
});

app.get("/logout", (req, res) => {
  clearLoginCookies(res);
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(PORT, () => console.log(`Auth Hub running on port ${PORT}`));
