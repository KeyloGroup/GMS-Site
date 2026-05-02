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
  "DB_HOST_ACCOUNTS",
  "DB_USER_ACCOUNTS",
  "DB_PASS_ACCOUNTS",
  "DB_NAME_ACCOUNTS",
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
      // try next candidate
    }
  }

  throw new Error("DECRYPT_ALL_KEYS_FAILED");
}

// PG_URL_USERDATA is truncated in .env (shell redirect character broke the value).
// Use the individual DB_* vars instead — all confirmed present and correct.
const userdataPool = new Pool({
  host:     process.env.DB_HOST_ACCOUNTS,
  user:     process.env.DB_USER_ACCOUNTS,
  password: process.env.DB_PASS_ACCOUNTS,
  database: process.env.DB_NAME_ACCOUNTS,
  port:     5432,
  ssl:      false,
});

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

// ─── BIO CODE HELPERS ─────────────────────────────────────────────────────────
//
// Storing the code in req.session is unreliable for unauthenticated visitors
// because saveUninitialized:false means Express won't always persist a fresh
// session between the /api/roblox/code GET and the /api/roblox/check-bio GET.
// We key off req.sessionID (stable once the cookie is set) and write straight
// to Redis with a hard TTL, completely bypassing the session store.
//
const BIO_CODE_TTL_SECS    = 10 * 60; // 10 minutes
const VERIFIED_ID_TTL_SECS = 15 * 60; // 15 minutes — survives to POST /api/register

function bioCodeKey(sid)    { return `biocode:${sid}`;    }
function verifiedIdKey(sid) { return `verifiedid:${sid}`; }

async function storeBioCode(sid, code) {
  await redisClient.set(bioCodeKey(sid), code, { EX: BIO_CODE_TTL_SECS });
}
async function getBioCode(sid) {
  return redisClient.get(bioCodeKey(sid));
}
async function deleteBioCode(sid) {
  await redisClient.del(bioCodeKey(sid));
}

async function storeVerifiedId(sid, robloxId) {
  await redisClient.set(verifiedIdKey(sid), robloxId, { EX: VERIFIED_ID_TTL_SECS });
}
async function getVerifiedId(sid) {
  return redisClient.get(verifiedIdKey(sid));
}
async function deleteVerifiedId(sid) {
  await redisClient.del(verifiedIdKey(sid));
}

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
  if (data.attempts >= 20)      lockMs = 24 * 60 * 60 * 1000;
  else if (data.attempts >= 10) lockMs = 15 * 60 * 1000;
  else if (data.attempts >= 5)  lockMs = 60 * 1000;

  if (lockMs > 0) data.lockedUntil = Date.now() + lockMs;

  const ttl = Math.ceil((lockMs || 24 * 60 * 60 * 1000) / 1000);
  await redisClient.set(key, JSON.stringify(data), { EX: ttl });
  console.log("BRUTE_FORCE_ATTEMPT", { attempts: data.attempts, lockedUntil: data.lockedUntil || null });
}

async function clearFailedAttempts(accountHmac) {
  await redisClient.del(`lockout:${accountHmac}`);
}

// ── A: Global DDoS rate limiter ───────────────────────────────────────────────
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
    next();
  }
}

// ── B: Auth-route rate limiter ────────────────────────────────────────────────
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
    // Must be true: unauthenticated visitors need a stable persisted session ID
    // before /api/roblox/code fires, otherwise Redis has nothing to look up on
    // the subsequent /api/roblox/check-bio call.
    saveUninitialized: true,
    proxy: true,
    cookie: {
      secure: true,
      httpOnly: true,
      // "lax" is correct here — all auth requests (register, login, OAuth
      // callback) are same-site navigations to keylogroup.co.uk.
      // "none" was causing the browser to reject the cookie because it requires
      // a Partitioned attribute in modern Chrome, and also caused the session ID
      // to change on every request (confirmed in logs).
      sameSite: "lax",
      // No domain override — let the browser scope the cookie to the exact host
      // (keylogroup.co.uk). Setting domain: ".keylogroup.co.uk" means the cookie
      // is sent to ALL subdomains including app.keylogroup.co.uk which runs a
      // separate app and could shadow or clobber the session.
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

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
    sameSite: "lax",
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

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.render("index", { title: "Keylo" });
});

// ── Roblox OAuth start ────────────────────────────────────────────────────────
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

// ── Roblox OAuth callback ─────────────────────────────────────────────────────
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

    const robloxId       = userRes.data.sub;
    const robloxUsername = userRes.data.name;
    const avatarUrl      = userRes.data.picture;
    const robloxIdHmac   = hmacLookup(robloxId);

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

// ── GET /register ─────────────────────────────────────────────────────────────
app.get("/register", csrfProtection, (req, res) => {
  if (req.query.oauth === "success" && req.session.pendingRoblox) {
    const { robloxUsername, avatarUrl } = req.session.pendingRoblox;
    return res.render("register", {
      title: "Complete Registration",
      csrfToken: req.csrfToken(),
      oauthFlow: true,
      robloxUsername,
      avatarUrl,
    });
  }

  res.render("register", {
    title: "Create Account",
    csrfToken: req.csrfToken(),
    oauthFlow: false,
    robloxUsername: null,
    avatarUrl: null,
  });
});

// ── POST /api/register ────────────────────────────────────────────────────────
app.post("/api/register", authRateLimiter, csrfProtection, async (req, res) => {
  console.log("API_REGISTER_HIT", {
    hasOAuthPending: !!req.session.pendingRoblox,
    sessionID: req.sessionID,
  });

  try {
    const { password, _hp } = req.body;

    // Honeypot
    if (_hp && _hp.length > 0) {
      console.log("HONEYPOT_TRIGGERED_REGISTER");
      await new Promise((r) => setTimeout(r, 2000));
      return res.redirect("https://app.keylogroup.co.uk/");
    }

    // Resolve identity — OAuth session takes priority, then Redis-verified ID
    let robloxId;
    if (req.session.pendingRoblox) {
      robloxId = req.session.pendingRoblox.robloxId;
    } else {
      robloxId = await getVerifiedId(req.sessionID);
    }

    if (!robloxId) {
      console.warn("API_REGISTER_NO_IDENTITY", { sessionID: req.sessionID });
      return res.status(400).send("Missing verified identity. Please restart registration.");
    }

    // Password validation
    if (!password || typeof password !== "string" || password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters.");
    }
    if (password.length > 128) {
      return res.status(400).send("Password too long.");
    }

    const robloxIdHmac = hmacLookup(robloxId);

    // Duplicate check — auto-login if account already exists
    const existing = await dbQuery(
      'SELECT id FROM "Accounts" WHERE roblox_id_hmac=$1 LIMIT 1',
      [robloxIdHmac]
    );
    if (existing.rows.length > 0) {
      console.log("API_REGISTER_ALREADY_EXISTS_AUTO_LOGIN", { robloxIdHmac });
      req.session.pendingRoblox = null;
      req.session.loggedIn      = true;
      await deleteVerifiedId(req.sessionID);
      return req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
    }

    // Ban check
    const banned = await dbQuery(
      'SELECT reason FROM "AccountsBan" WHERE roblox_id_hmac=$1 LIMIT 1',
      [robloxIdHmac]
    );
    if (banned.rows.length > 0) {
      return res.redirect(
        `https://keylogroup.co.uk/account/restricted?reason=${encodeURIComponent(
          banned.rows[0].reason || "Restricted"
        )}`
      );
    }

    // Persist
    const encryptedId       = encrypt(robloxId);
    const encryptedPassword = encrypt(password);

    await dbQuery(
      'INSERT INTO "Accounts" (roblox_id, roblox_id_hmac, encrypted_password) VALUES ($1, $2, $3)',
      [encryptedId, robloxIdHmac, encryptedPassword]
    );

    // Clean up
    req.session.pendingRoblox = null;
    req.session.loggedIn      = true;
    await deleteVerifiedId(req.sessionID);
    await deleteBioCode(req.sessionID);

    console.log("API_REGISTER_SUCCESS", { robloxIdHmac });
    req.session.save(() => res.redirect("https://app.keylogroup.co.uk/"));
  } catch (err) {
    console.error("API_REGISTER_EXCEPTION", { message: err.message, stack: err.stack });
    res.status(500).send("Registration failed. Please try again.");
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ROBLOX API ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /api/roblox/user/:id ──────────────────────────────────────────────────
app.get("/api/roblox/user/:id", authRateLimiter, async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: "Invalid Roblox User ID — must be numeric." });
  }

  try {
    const usersRes = await axios.post(
      "https://users.roblox.com/v1/users",
      { userIds: [parseInt(id, 10)], excludeBannedUsers: false },
      { headers: { "Content-Type": "application/json" }, timeout: 5000 }
    );

    const users = usersRes.data?.data;
    if (!users || users.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = users[0];

    let avatarUrl = "/icons/default-avatar.png";
    try {
      const thumbRes = await axios.get(
        `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${user.id}&size=150x150&format=Png&isCircular=false`,
        { timeout: 5000 }
      );
      const thumb = thumbRes.data?.data?.[0];
      if (thumb?.imageUrl) avatarUrl = thumb.imageUrl;
    } catch {
      console.warn("ROBLOX_AVATAR_FETCH_FAILED", { userId: user.id });
    }

    console.log("ROBLOX_USER_LOOKUP", { id: user.id, name: user.name });
    return res.json({ id: String(user.id), name: user.name, avatar: avatarUrl });
  } catch (err) {
    console.error("ROBLOX_USER_LOOKUP_ERROR", { message: err.message, id });
    return res.status(500).json({ error: "Failed to look up Roblox user." });
  }
});

// ── GET /api/roblox/code ──────────────────────────────────────────────────────
// Writes the code straight to Redis under req.sessionID — no session save needed.
app.get("/api/roblox/code", authRateLimiter, async (req, res) => {
  try {
    const raw  = crypto.randomBytes(4).toString("hex").toUpperCase();
    const code = `KL-${raw}`;

    await storeBioCode(req.sessionID, code);

    console.log("BIO_CODE_ISSUED", { sessionID: req.sessionID, code });
    res.json({ code });
  } catch (err) {
    console.error("BIO_CODE_ISSUE_ERROR", { message: err.message });
    res.status(500).json({ error: "Failed to generate code. Please try again." });
  }
});

// ── GET /api/roblox/check-bio/:userId/:code ───────────────────────────────────
// Reads the stored code straight from Redis — no session lookup needed.
app.get("/api/roblox/check-bio/:userId/:code", authRateLimiter, async (req, res) => {
  const { userId, code } = req.params;

  if (!/^\d+$/.test(userId)) {
    return res.status(400).json({ success: false, error: "Invalid user ID." });
  }

  // Only allow the exact format we generate: KL- followed by 8 uppercase hex chars
  if (!/^KL-[0-9A-F]{8}$/.test(code)) {
    return res.status(400).json({ success: false, error: "Malformed code." });
  }

  try {
    const storedCode = await getBioCode(req.sessionID);

    console.log("BIO_CODE_CHECK", {
      sessionID: req.sessionID,
      storedCode,
      receivedCode: code,
    });

    if (!storedCode) {
      return res.status(400).json({
        success: false,
        error: "No pending code found. Please go back and generate a new code.",
      });
    }

    if (storedCode !== code) {
      return res.status(400).json({
        success: false,
        error: "Code mismatch. Please go back and copy the code exactly as shown.",
      });
    }

    // Fetch the user's Roblox bio
    const profileRes = await axios.get(
      `https://users.roblox.com/v1/users/${userId}`,
      { timeout: 5000 }
    );

    const bio = profileRes.data?.description || "";
    console.log("BIO_CONTENT", { userId, bio: bio.slice(0, 100) });

    if (!bio.includes(code)) {
      return res.json({
        success: false,
        error: "Code not found in bio. Make sure you saved your Roblox profile and try again.",
      });
    }

    // Confirmed — delete used code, store verified ID, both in Redis
    await deleteBioCode(req.sessionID);
    await storeVerifiedId(req.sessionID, userId);

    console.log("BIO_CODE_VERIFIED", { userId, sessionID: req.sessionID });
    return res.json({ success: true });
  } catch (err) {
    console.error("BIO_CHECK_ERROR", { message: err.message, userId });
    return res.status(500).json({ success: false, error: "Could not reach Roblox. Please try again." });
  }
});

// ── GET /api/roblox/username/:id ──────────────────────────────────────────────
// Returns username only for the session-verified Roblox ID.
app.get("/api/roblox/username/:id", authRateLimiter, async (req, res) => {
  const { id } = req.params;

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ success: false, error: "Invalid user ID." });
  }

  try {
    const verifiedId = await getVerifiedId(req.sessionID);
    if (!verifiedId || verifiedId !== id) {
      return res.status(403).json({ success: false, error: "Not authorized." });
    }

    const r = await axios.get(`https://users.roblox.com/v1/users/${id}`, { timeout: 5000 });
    return res.json({ success: true, username: r.data.name });
  } catch (err) {
    console.error("USERNAME_FETCH_ERROR", { message: err.message, id });
    return res.status(500).json({ success: false, error: "Failed to fetch username." });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// REMAINING ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get("/login", csrfProtection, (req, res) => {
  res.render("login", {
    csrfToken: req.csrfToken(),
    oauthSuccess: req.query.oauth === "success",
    robloxUsername: req.query.username || "",
    robloxId: req.query.id || "",
  });
});

app.post("/login", authRateLimiter, csrfProtection, async (req, res) => {
  console.log("ROUTE_LOGIN_POST");
  try {
    const { robloxId, password, _hp } = req.body;

    if (_hp && _hp.length > 0) {
      console.log("HONEYPOT_TRIGGERED_LOGIN");
      await new Promise((r) => setTimeout(r, 2000));
      return res.redirect("https://app.keylogroup.co.uk/");
    }

    if (!robloxId || !password) return res.status(400).send("Missing credentials");

    const accountHmac = hmacLookup(robloxId);

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
      return res.status(401).send("Invalid credentials");
    }

    let storedPassword;
    try {
      storedPassword = decrypt(users.rows[0].encrypted_password);
    } catch (decryptErr) {
      console.error("LOGIN_DECRYPT_FAILED", { message: decryptErr.message });
      return res.status(500).send("Login failed");
    }

    const maxLen = Math.max(password.length, storedPassword.length);
    const inputBuf  = Buffer.alloc(maxLen);
    const storedBuf = Buffer.alloc(maxLen);
    inputBuf.write(password, "utf8");
    storedBuf.write(storedPassword, "utf8");
    const lengthMatch = password.length === storedPassword.length;
    const bytesMatch  = crypto.timingSafeEqual(inputBuf, storedBuf);
    const match       = lengthMatch && bytesMatch;

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