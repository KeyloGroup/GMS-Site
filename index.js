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

["PG_URL_USERDATA", "ROBLOX_OAUTH_CLIENT_ID", "ROBLOX_OAUTH_CLIENT_SECRET", "ROBLOX_OAUTH_REDIRECT_URI", "SESSION_SECRET", "REDIS_URL"].forEach((v) => {
  if (!process.env[v]) {
    console.error("ENV_MISSING", { key: v });
    process.exit(1);
  }
});

const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });
async function dbQuery(text, params) {
  console.log("DB_QUERY", { text, params });
  const res = await userdataPool.query(text, params);
  console.log("DB_RESULT", { rowCount: res.rowCount });
  return res;
}

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on("error", (err) => console.error("REDIS_ERROR", { message: err.message }));
redisClient.connect().then(() => console.log("REDIS_CONNECTED", { url: process.env.REDIS_URL }));

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
  console.log("REQ_IN", { method: req.method, url: req.originalUrl, cookies: req.cookies});
  const originalRedirect = res.redirect.bind(res);
  res.redirect = (url) => {
    console.log("RES_REDIRECT", { from: req.originalUrl, to: url, statusCode: res.statusCode });
    return originalRedirect(url);
  };
  const originalRender = res.render.bind(res);
  res.render = (view, data) => {
    console.log("RES_RENDER", { view, keys: data ? Object.keys(data) : [] });
    return originalRender(view, data);
  };
  next();
});

app.use(session({
  store: new RedisStore({ client: redisClient }),
  name: "keylo.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: { secure: true, httpOnly: true, sameSite: "none", domain: ".keylogroup.co.uk", maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
  console.log("SESSION_STATE", { sessionID: req.sessionID, session: { oauthState: req.session.oauthState, loggedIn: req.session.loggedIn, hasPendingRoblox: !!req.session.pendingRoblox } });
  next();
});

const csrfProtection = csurf({ cookie: { secure: true, httpOnly: true, sameSite: "none", domain: ".keylogroup.co.uk", path: "/" } });

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

function setLoginCookies(res, { id, username, avatar }) {
  const opts = { secure: true, sameSite: "none", httpOnly: false, domain: ".keylogroup.co.uk", path: "/", maxAge: 30 * 24 * 60 * 60 * 1000 };
  console.log("COOKIES_SET", { id, username, avatar });
  res.cookie("id", String(id), opts);
  res.cookie("username", String(username), opts);
  res.cookie("avatar", String(avatar), opts);
}

function clearLoginCookies(res) {
  const opts = { secure: true, sameSite: "none", httpOnly: false, domain: ".keylogroup.co.uk", path: "/" };
  console.log("COOKIES_CLEAR", { cookies: ["id", "username", "avatar", "theme"] });
  ["id", "username", "avatar", "theme"].forEach((c) => res.clearCookie(c, opts));
}

app.get("/", (req, res) => {
  console.log("ROUTE_ROOT");
  res.render("index", { title: "Keylo" });
});

app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  console.log("OAUTH_START", { state, sessionID: req.sessionID });
  req.session.save(() => {
    const url = "https://apis.roblox.com/oauth/v1/authorize?" + querystring.stringify({ client_id: process.env.ROBLOX_OAUTH_CLIENT_ID, response_type: "code", redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI, scope: "openid profile", state });
    console.log("OAUTH_REDIRECT_AUTHORIZE", { url });
    res.redirect(url);
  });
});

app.get("/auth/roblox/callback", async (req, res) => {
  console.log("OAUTH_CALLBACK_HIT", { query: req.query, sessionID: req.sessionID, sessionOauthState: req.session.oauthState });
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(error_description || error);
    if (!code || !state || state !== req.session.oauthState) return res.status(400).send("Invalid OAuth session");
    const tokenRes = await axios.post("https://apis.roblox.com/oauth/v1/token", querystring.stringify({ grant_type: "authorization_code", client_id: process.env.ROBLOX_OAUTH_CLIENT_ID, client_secret: process.env.ROBLOX_OAUTH_CLIENT_SECRET, code, redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI }), { headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", { headers: { Authorization: `Bearer ${tokenRes.data.access_token}` } });
    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;
    const banned = await dbQuery('SELECT * FROM "AccountsBan" WHERE username=$1 LIMIT 1', [robloxUsername]);
    if (banned.rows.length > 0) return res.redirect(`https://keylogroup.co.uk/account/restricted?reason=${encodeURIComponent(banned.rows[0].reason || "Restricted")}`);
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
    console.error("OAUTH_CALLBACK_EXCEPTION", { message: err.message, stack: err.stack });
    clearLoginCookies(res);
    res.status(500).send("OAuth failed");
  }
});

app.get("/register", csrfProtection, (req, res) => {
  const pending = req.session.pendingRoblox;
  console.log("ROUTE_REGISTER", { query: req.query, hasPending: !!pending });
  if (req.query.oauth === "success" && pending) return res.render("passwordregister", { title: "Complete Registration", csrfToken: req.csrfToken(), robloxUsername: pending.robloxUsername, avatarUrl: pending.avatarUrl });
  res.render("register", { title: "Register", csrfToken: req.csrfToken() });
});

app.post("/api/register", csrfProtection, async (req, res) => {
  console.log("API_REGISTER_HIT", { bodyKeys: Object.keys(req.body || {}), hasPending: !!req.session.pendingRoblox });
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).send("Password too short");
    const hashed = await bcrypt.hash(password, 12);
    await dbQuery('INSERT INTO "Accounts" ("roblox username","hashed password") VALUES ($1,$2)', [pending.robloxUsername, hashed]);
    req.session.pendingRoblox = null;
    req.session.loggedIn = true;
    console.log("API_REGISTER_SUCCESS", { robloxUsername: pending.robloxUsername });
    res.redirect("https://app.keylogroup.co.uk/");
  } catch (err) {
    console.error("API_REGISTER_EXCEPTION", { message: err.message, stack: err.stack });
    res.status(500).send("Registration failed");
  }
});

app.get("/login", csrfProtection, (req, res) => {
  console.log("ROUTE_LOGIN_GET", { query: req.query });
  res.render("login", { csrfToken: req.csrfToken(), oauthSuccess: req.query.oauth === "success", robloxUsername: req.query.username || "", robloxId: req.query.id || "" });
});

app.post("/login", csrfProtection, async (req, res) => {
  console.log("ROUTE_LOGIN_POST", { bodyKeys: Object.keys(req.body || {}) });
  try {
    const { robloxUsername, password } = req.body;
    if (!robloxUsername || !password) return res.status(400).send("Missing credentials");
    const users = await dbQuery('SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1', [robloxUsername]);
    if (!users.rows.length) return res.status(401).send("User not found");
    const match = await bcrypt.compare(password, users.rows[0]["hashed password"]);
    if (!match) return res.status(401).send("Invalid password");
    req.session.loggedIn = true;
    console.log("LOGIN_SUCCESS", { robloxUsername });
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    console.error("LOGIN_EXCEPTION", { message: err.message, stack: err.stack });
    res.status(500).send("Login failed");
  }
});

app.get("/logout", (req, res) => {
  console.log("ROUTE_LOGOUT", { sessionID: req.sessionID });
  clearLoginCookies(res);
  req.session.destroy(() => {
    console.log("SESSION_DESTROYED", { sessionID: req.sessionID });
    res.redirect("/");
  });
});

app.use((req, res) => {
  console.log("ROUTE_404", { url: req.originalUrl });
  res.status(404).render("404");
});

app.use((err, req, res, next) => {
  console.error("UNCAUGHT_ERROR", { message: err.message, stack: err.stack, url: req.originalUrl });
  res.status(500).send("Internal server error");
});

app.listen(PORT, () => console.log("SERVER_START", { host: "keylogroup.co.uk", port: PORT }));
