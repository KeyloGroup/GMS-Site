const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { createClient } = require("redis");
const { RedisStore } = require("connect-redis");
const crypto = require("crypto");
const axios = require("axios");
const querystring = require("querystring");
const { Pool } = require("pg");
const csurf = require("csurf");
require("dotenv").config({ path: "/root/KeyloENV/.env" });

const app = express();
app.set("trust proxy", 1);
const PORT = 3000;

[
  "PG_URL_USERDATA",
  "ROBLOX_OAUTH_CLIENT_ID",
  "ROBLOX_OAUTH_CLIENT_SECRET",
  "ROBLOX_OAUTH_REDIRECT_URI",
  "SESSION_SECRET",
  "REDIS_URL",
  "ENCRYPTION_MASTER_SECRET",
].forEach((v) => {
  if (!process.env[v]) {
    console.error("ENV_MISSING", { key: v });
    process.exit(1);
  }
});

// ─── AES-256-GCM WITH DAILY KEY ROTATION ─────────────────────────────────────
//
// Every field written to the DB is encrypted with AES-256-GCM.
// Key rotates daily via HKDF(ENCRYPTION_MASTER_SECRET, date).
// Decrypt tries the blob's own date key + KEY_LOOKBACK_DAYS fallback.
//
// Blob format (base64 of): "<YYYY-MM-DD>.<iv_hex>.<authTag_hex>.<ciphertext_hex>"


const KEY_LOOKBACK_DAYS = 7;
const KEY_LENGTH = 32;

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function deriveDailyKey(dateStr) {
  return crypto.hkdfSync(
    "sha256",
    Buffer.from(process.env.ENCRYPTION_MASTER_SECRET, "utf8"),
    Buffer.alloc(0),
    Buffer.from(`keylo-aes256gcm-v1-${dateStr}`, "utf8"),
    KEY_LENGTH
  );
}

function encrypt(plaintext) {
  const dateStr = todayUTC();
  const key = deriveDailyKey(dateStr);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = `${dateStr}.${iv.toString("hex")}.${tag.toString("hex")}.${ct.toString("hex")}`;
  return Buffer.from(blob, "utf8").toString("base64");
}

function decrypt(base64Blob) {
  const blob = Buffer.from(base64Blob, "base64").toString("utf8");
  const parts = blob.split(".");
  if (parts.length !== 4) throw new Error("DECRYPT_MALFORMED_BLOB");
  const [blobDate, ivHex, tagHex, ctHex] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const ct = Buffer.from(ctHex, "hex");

  const candidates = new Set([blobDate, todayUTC()]);
  for (let i = 1; i <= KEY_LOOKBACK_DAYS; i++) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    candidates.add(d.toISOString().slice(0, 10));
  }

  for (const dateStr of candidates) {
    try {
      const key = deriveDailyKey(dateStr);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
    } catch {
    }
  }

  throw new Error("DECRYPT_ALL_KEYS_FAILED");
}

const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });

async function dbQuery(text, params) {
  console.log("DB_QUERY", { text, params });
  const res = await userdataPool.query(text, params);
  console.log("DB_RESULT", { rowCount: res.rowCount });
  return res;
}

function hmacLookup(value) {
  return crypto
    .createHmac("sha256", process.env.ENCRYPTION_MASTER_SECRET)
    .update(String(value))
    .digest("hex");
}

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on("error", (err) => console.error("REDIS_ERROR", { message: err.message }));
redisClient.connect().then(() => console.log("REDIS_CONNECTED"));

function requestFingerprint(req) {
  const raw = [
    req.headers["user-agent"] || "",
    req.headers["accept-language"] || "",
    req.headers["accept-encoding"] || "",
    req.headers["accept"] || "",
  ].join("|");
  return crypto
    .createHmac("sha256", process.env.ENCRYPTION_MASTER_SECRET)
    .update(raw)
    .digest("hex")
    .slice(0, 32);
}

async function slidingWindowCheck(key, limit, windowSecs) {
  const now = Date.now();
  const windowStart = now - windowSecs * 1000;
  const redisKey = `rl:${key}`;

  const pipe = redisClient.multi();
  pipe.zRemRangeByScore(redisKey, "-inf", windowStart);
  pipe.zAdd(redisKey, { score: now, value: `${now}-${crypto.randomBytes(4).toString("hex")}` });
  pipe.zCard(redisKey);
  pipe.expire(redisKey, windowSecs + 1);
  const results = await pipe.exec();

  const count = results[2];
  const allowed = count <= limit;
  const remaining = Math.max(0, limit - count);

  let retryAfter = 0;
  if (!allowed) {
    const oldest = await redisClient.zRangeWithScores(redisKey, 0, 0);
    if (oldest && oldest.length > 0) {
      retryAfter = Math.ceil((oldest[0].score + windowSecs * 1000 - now) / 1000);
    }
  }

  return { allowed, remaining, retryAfter: Math.max(0, retryAfter) };
}

async function checkAccountLockout(accountHmac) {
  const key = `lockout:${accountHmac}`;
  const raw = await redisClient.get(key);
  if (!raw) return { locked: false, attempts: 0 };
  const data = JSON.parse(raw);
  if (data.lockedUntil && Date.now() < data.lockedUntil) {
    return {
      locked: true,
      retryAfter: Math.ceil((data.lockedUntil - Date.now()) / 1000),
      attempts: data.attempts,
    };
  }
  return { locked: false, attempts: data.attempts || 0 };
}

async function recordFailedAttempt(accountHmac) {
  const key = `lockout:${accountHmac}`;
  const raw = await redisClient.get(key);
  const data = raw ? JSON.parse(raw) : { attempts: 0 };
  data.attempts = (data.attempts || 0) + 1;

  let lockMs = 0;
  if (data.attempts >= 20)      lockMs = 24 * 60 * 60 * 1000; // 24 hours
  else if (data.attempts >= 10) lockMs = 15 * 60 * 1000;      // 15 minutes
  else if (data.attempts >= 5)  lockMs = 60 * 1000;           // 1 minute

  if (lockMs > 0) data.lockedUntil = Date.now() + lockMs;

  const ttl = Math.ceil((lockMs || 24 * 60 * 60 * 1000) / 1000);
  await redisClient.set(key, JSON.stringify(data), { EX: ttl });
  console.log("BRUTE_FORCE_ATTEMPT", { attempts: data.attempts, lockedUntil: data.lockedUntil || null });
}

async function clearFailedAttempts(accountHmac) {
  await redisClient.del(`lockout:${accountHmac}`);
}

// ── A: Global DDoS rate limiter — all routes ──────────────────────────────────
async function globalRateLimiter(req, res, next) {
  try {
    const key = req.session?.id
      ? `sess:${req.session.id}`
      : `fp:${requestFingerprint(req)}`;

    const { allowed, remaining, retryAfter } = await slidingWindowCheck(key, 200, 60);

    res.set("X-RateLimit-Limit", "200");
    res.set("X-RateLimit-Remaining", String(remaining));

    if (!allowed) {
      console.log("RATELIMIT_GLOBAL_BLOCKED");
      res.set("Retry-After", String(retryAfter));
      return res.status(429).send("Too many requests. Please slow down.");
    }
    next();
  } catch (err) {
    console.error("RATELIMIT_ERROR", { message: err.message });
    next(); // fail open — don't break app on Redis hiccup
  }
}

// ── B: Auth-route rate limiter — /login + /api/register ──────────────────────
async function authRateLimiter(req, res, next) {
  try {
    const key = `authfp:${requestFingerprint(req)}`;
    const { allowed, remaining, retryAfter } = await slidingWindowCheck(key, 15, 600);

    res.set("X-RateLimit-Limit", "15");
    res.set("X-RateLimit-Remaining", String(remaining));

    if (!allowed) {
      console.log("RATELIMIT_AUTH_BLOCKED");
      res.set("Retry-After", String(retryAfter));
      return res.status(429).send("Too many authentication attempts. Please wait before trying again.");
    }
    next();
  } catch (err) {
    console.error("AUTH_RATELIMIT_ERROR", { message: err.message });
    next();
  }
}

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
  console.log("REQ_IN", { method: req.method, url: req.originalUrl });
  const originalRedirect = res.redirect.bind(res);
  res.redirect = (url) => {
    console.log("RES_REDIRECT", { from: req.originalUrl, to: url });
    return originalRedirect(url);
  };
  const originalRender = res.render.bind(res);
  res.render = (view, data) => {
    console.log("RES_RENDER", { view, keys: data ? Object.keys(data) : [] });
    return originalRender(view, data);
  };
  next();
});

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
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

// Global DDoS limiter applied after session so we can prefer session ID as key
app.use(globalRateLimiter);

app.use((req, res, next) => {
  console.log("SESSION_STATE", {
    sessionID: req.sessionID,
    loggedIn: req.session.loggedIn,
    hasPendingRoblox: !!req.session.pendingRoblox,
  });
  next();
});

const csrfProtection = csurf({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none",
    domain: ".keylogroup.co.uk",
    path: "/",
  },
});

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

function setLoginCookies(res, { id, username, avatar }) {
  const opts = {
    secure: true,
    sameSite: "none",
    httpOnly: false,
    domain: ".keylogroup.co.uk",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  };
  res.cookie("id", String(id), opts);
  res.cookie("username", String(username), opts);
  res.cookie("avatar", String(avatar), opts);
}

function clearLoginCookies(res) {
  const opts = { secure: true, sameSite: "none", httpOnly: false, domain: ".keylogroup.co.uk", path: "/" };
  ["id", "username", "avatar", "theme"].forEach((c) => res.clearCookie(c, opts));
}


app.get("/", (req, res) => {
  res.render("index", { title: "Keylo" });
});

app.get("/auth/roblox", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  console.log("OAUTH_START", { sessionID: req.sessionID });
  req.session.save(() => {
    const url =
      "https://apis.roblox.com/oauth/v1/authorize?" +
      querystring.stringify({
        client_id: process.env.ROBLOX_OAUTH_CLIENT_ID,
        response_type: "code",
        redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
        scope: "openid profile",
        state,
      });
    res.redirect(url);
  });
});

app.get("/auth/roblox/callback", async (req, res) => {
  console.log("OAUTH_CALLBACK_HIT", { sessionID: req.sessionID });
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
        redirect_uri: process.env.ROBLOX_OAUTH_REDIRECT_URI,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const userRes = await axios.get("https://apis.roblox.com/oauth/v1/userinfo", {
      headers: { Authorization: `Bearer ${tokenRes.data.access_token}` },
    });

    const robloxId = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl = userRes.data.picture;

    const robloxIdHmac = hmacLookup(robloxId);

    const banned = await dbQuery(
      'SELECT * FROM "AccountsBan" WHERE roblox_id_hmac=$1 LIMIT 1',
      [robloxIdHmac]
    );
    if (banned.rows.length > 0) {
      return res.redirect(
        `https://keylogroup.co.uk/account/restricted?reason=${encodeURIComponent(
          banned.rows[0].reason || "Restricted"
        )}`
      );
    }

    const existing = await dbQuery(
      'SELECT * FROM "Accounts" WHERE roblox_id_hmac=$1 LIMIT 1',
      [robloxIdHmac]
    );

    clearLoginCookies(res);
    setLoginCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl });
    req.session.oauthState = null;

    if (existing.rows.length > 0) {
      req.session.loggedIn = true;
      return req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
    }

    req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
    req.session.save((err) => {
      if (err) {
        console.error("SESSION_SAVE_FAILED", err);
        return res.status(500).send("Session error");
      }
      res.redirect("/register?oauth=success");
    });
  } catch (err) {
    console.error("OAUTH_CALLBACK_EXCEPTION", { message: err.message });
    clearLoginCookies(res);
    res.status(500).send("OAuth failed");
  }
});

app.get("/register", csrfProtection, (req, res) => {
  const pending = req.session.pendingRoblox;
  if (req.query.oauth === "success" && pending) {
    return res.render("passwordregister", {
      title: "Complete Registration",
      csrfToken: req.csrfToken(),
      robloxUsername: pending.robloxUsername,
      avatarUrl: pending.avatarUrl,
    });
  }
  res.render("register", { title: "Register", csrfToken: req.csrfToken() });
});

app.post("/api/register", authRateLimiter, csrfProtection, async (req, res) => {
  console.log("API_REGISTER_HIT", { hasPending: !!req.session.pendingRoblox });
  try {
    const pending = req.session.pendingRoblox;
    if (!pending) return res.status(400).send("Missing OAuth session");

    const { password, _hp } = req.body;

    if (_hp && _hp.length > 0) {
      console.log("HONEYPOT_TRIGGERED_REGISTER");
      await new Promise((r) => setTimeout(r, 2000)); // waste bot time
      return res.redirect("https://app.keylogroup.co.uk/"); // fake success
    }

    if (!password || password.length < 8)
      return res.status(400).send("Password must be at least 8 characters");

    const encryptedId = encrypt(pending.robloxId);
    const encryptedPassword = encrypt(password);
    const robloxIdHmac = hmacLookup(pending.robloxId);

    await dbQuery(
      'INSERT INTO "Accounts" (roblox_id, roblox_id_hmac, encrypted_password) VALUES ($1, $2, $3)',
      [encryptedId, robloxIdHmac, encryptedPassword]
    );

    req.session.pendingRoblox = null;
    req.session.loggedIn = true;
    console.log("API_REGISTER_SUCCESS");
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    console.error("API_REGISTER_EXCEPTION", { message: err.message });
    res.status(500).send("Registration failed");
  }
});

app.get("/login", csrfProtection, (req, res) => {
  res.render("login", {
    csrfToken: req.csrfToken(),
    oauthSuccess: req.query.oauth === "success",
    robloxUsername: req.query.username || "",
    robloxId: req.query.id || "",
  });
});

// ── Login POST — auth rate limited + brute force lockout + honeypot ──
app.post("/login", authRateLimiter, csrfProtection, async (req, res) => {
  console.log("ROUTE_LOGIN_POST");
  try {
    const { robloxId, password, _hp } = req.body;

    // ── D: Honeypot ──
    if (_hp && _hp.length > 0) {
      console.log("HONEYPOT_TRIGGERED_LOGIN");
      await new Promise((r) => setTimeout(r, 2000));
      return res.redirect("https://app.keylogroup.co.uk/");
    }

    if (!robloxId || !password) return res.status(400).send("Missing credentials");

    const accountHmac = hmacLookup(robloxId);

    // ── C: Brute-force lockout check ──
    const lockout = await checkAccountLockout(accountHmac);
    if (lockout.locked) {
      console.log("BRUTE_FORCE_LOCKED", { retryAfter: lockout.retryAfter });
      res.set("Retry-After", String(lockout.retryAfter));
      return res
        .status(429)
        .send(`Account temporarily locked. Try again in ${Math.ceil(lockout.retryAfter / 60)} minute(s).`);
    }

    const users = await dbQuery(
      'SELECT * FROM "Accounts" WHERE roblox_id_hmac=$1 LIMIT 1',
      [accountHmac]
    );

    if (!users.rows.length) {
      await recordFailedAttempt(accountHmac);
      return res.status(401).send("Invalid credentials"); // vague on purpose
    }

    let storedPassword;
    try {
      storedPassword = decrypt(users.rows[0].encrypted_password);
    } catch (decryptErr) {
      console.error("LOGIN_DECRYPT_FAILED", { message: decryptErr.message });
      return res.status(500).send("Login failed");
    }

    const maxLen = Math.max(password.length, storedPassword.length);
    const inputBuf = Buffer.alloc(maxLen);
    const storedBuf = Buffer.alloc(maxLen);
    inputBuf.write(password, "utf8");
    storedBuf.write(storedPassword, "utf8");
    const lengthMatch = password.length === storedPassword.length;
    const bytesMatch = crypto.timingSafeEqual(inputBuf, storedBuf);
    const match = lengthMatch && bytesMatch;

    if (!match) {
      await recordFailedAttempt(accountHmac);
      return res.status(401).send("Invalid credentials");
    }

    await clearFailedAttempts(accountHmac);
    req.session.loggedIn = true;
    console.log("LOGIN_SUCCESS");
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    console.error("LOGIN_EXCEPTION", { message: err.message });
    res.status(500).send("Login failed");
  }
});

app.get("/settings", csrfProtection, (req, res) => {
  res.render("workspacesettings", { csrfToken: req.csrfToken(), workspace: {} });
});

app.get("/logout", (req, res) => {
  console.log("ROUTE_LOGOUT", { sessionID: req.sessionID });
  clearLoginCookies(res);
  req.session.destroy(() => {
    console.log("SESSION_DESTROYED");
    res.redirect("/");
  });
});

app.get("/account/restricted", (req, res) => {
  const { reason, username } = req.query;
  res.render("banned", {
    username: username || "User",
    reason: reason || "Restricted",
    redirectUrl: "/",
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