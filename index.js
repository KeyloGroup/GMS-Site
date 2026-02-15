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
app.set("trust proxy", 1);
const PORT = 3000;

const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex");

app.use(session({
    name: "keylo.sid",
    secret: SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    proxy: true,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: "none",
        domain: "keyloroblox.xyz",
        maxAge: 1000 * 60 * 60 * 24 * 30,
        path: "/"
    }
}));

const csrfProtection = csurf({
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: "none",
        domain: "keyloroblox.xyz",
        path: "/"
    }
});

app.use((req, res, next) => {
    if (["/auth/roblox", "/auth/roblox/callback", "/"].includes(req.path)) return next();
    return csrfProtection(req, res, next);
});

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

function setLoginCookies(res, { id, username, avatar }) {
    const base = {
        secure: true,
        sameSite: "none",
        httpOnly: false,
        maxAge: 1000 * 60 * 60 * 24 * 30,
        domain: "keyloroblox.xyz",
        path: "/"
    };
    res.cookie("id", String(id), base);
    res.cookie("username", String(username), base);
    res.cookie("avatar", String(avatar), base);
}

function clearLoginCookies(res) {
    const base = { secure: true, sameSite: "none", domain: "keyloroblox.xyz", path: "/" };
    ["id", "username", "avatar", "theme"].forEach(c => res.clearCookie(c, base));
}

app.get("/", (req, res) => res.render("index", { title: "Keylo" }));

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
        res.redirect(authUrl);
    });
});

app.get("/auth/roblox/callback", async (req, res) => {
    try {
        const { code, state } = req.query;
        if (!state || state !== req.session.oauthState) return res.status(400).send("Invalid state");

        const tokenRes = await axios.post("https://apis.roblox.com/oauth/v1/token", querystring.stringify({
            grant_type: "authorization_code",
            client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
            client_secret: process.env.ROBLOX_OAUTH_CLIENT_SECRET,
            code,
            redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI
        }));

        const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
            headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
        });

        const { sub: robloxId, name: robloxUsername, picture: avatarUrl } = userRes.data;
        const banned = await userdataPool.query('SELECT * FROM "AccountsBan" WHERE username = $1 LIMIT 1', [robloxUsername]);

        if (banned.rows.length > 0) {
            return res.redirect(`https://app.keyloroblox.xyz/account/restricted?reason=${encodeURIComponent(banned.rows[0].reason || "Restricted")}`);
        }

        const users = await userdataPool.query('SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1', [robloxUsername]);
        
        clearLoginCookies(res);
        setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });

        if (users.rows.length > 0) {
            req.session.oauthState = null;
            return req.session.save(() => res.redirect("https://app.keyloroblox.xyz/"));
        }

        req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
        res.redirect("/register?oauth=success");
    } catch (err) {
        res.status(500).send("OAuth Failed");
    }
});

app.get("/register", (req, res) => {
    const pending = req.session.pendingRoblox;
    if (req.query.oauth === "success" && pending) {
        return res.render("passwordregister", { title: "Register", csrfToken: req.csrfToken(), robloxUsername: pending.robloxUsername, avatarUrl: pending.avatarUrl });
    }
    res.render("register", { title: "Register", csrfToken: req.csrfToken() });
});

app.get("/login", (req, res) => res.render("login", { csrfToken: req.csrfToken(), oauthSuccess: req.query.oauth === "success", robloxUsername: req.query.username || "", robloxId: req.query.id || "" }));

app.post("/api/register", async (req, res) => {
    try {
        const pending = req.session.pendingRoblox;
        if (!pending) return res.status(400).send("No session");
        const hashedPassword = await bcrypt.hash(req.body.password, 12);
        await userdataPool.query('INSERT INTO "Accounts" ("roblox username", "hashed password") VALUES ($1, $2)', [pending.robloxUsername, hashedPassword]);
        setLoginCookies(res, { id: pending.robloxId, username: pending.robloxUsername, avatar: pending.avatarUrl });
        req.session.pendingRoblox = null;
        res.redirect("https://app.keyloroblox.xyz/");
    } catch (err) { res.status(500).send("Error"); }
});

app.post("/login", async (req, res) => {
    const { robloxUsername, password } = req.body;
    const users = await userdataPool.query('SELECT * FROM "Accounts" WHERE "roblox username" = $1 LIMIT 1', [robloxUsername]);
    if (users.rows.length && await bcrypt.compare(password, users.rows[0]["hashed password"])) {
        return res.redirect("https://app.keyloroblox.xyz/");
    }
    res.status(401).send("Invalid credentials");
});

app.get("/logout", (req, res) => {
    clearLoginCookies(res);
    req.session.destroy(() => res.redirect("/"));
});

app.listen(PORT, () => console.log(`Auth running on ${PORT}`));
