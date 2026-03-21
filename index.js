const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { createClient } = require("redis");
const { RedisStore } = require("connect-redis");
const axios = require("axios");
const csurf = require("csurf");
const { Pool } = require("pg");

require("dotenv").config({ path: "/root/KeyloENV/.env" });

const app = express();
app.set("trust proxy", 1);
const PORT = 3005;

// Env check
["PG_URL_WORKSPACES", "SESSION_SECRET", "REDIS_URL"].forEach((v) => {
  if (!process.env[v]) {
    console.error("ENV_MISSING", v);
    process.exit(1);
  }
});

// DB pool
const workspacesPool = new Pool({ connectionString: process.env.PG_URL_WORKSPACES });
async function dbQuery(text, params) { return workspacesPool.query(text, params); }

// Redis
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.on("error", (err) => console.error("REDIS_ERROR", err.message));
redisClient.connect();

// Middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session middleware (fixed domain)
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

// CSRF
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

// Auth helpers
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

function requireLogin(req, res, next) {
  const { id, username } = req.cookies;
  if (!id || !username) {
    clearLoginCookies(res);
    return res.redirect("https://keylogroup.co.uk/auth/roblox");
  }
  next();
}

// Roblox group check
async function robloxGroupRankCheck(robloxId, groupId, minRank) {
  try {
    if (!robloxId || !groupId || !minRank) return false;
    const response = await axios.get(
      `https://groups.roblox.com/v2/users/${robloxId}/groups/roles`,
      { timeout: 5000 }
    );
    const group = response.data?.data?.find((g) => String(g.group.id) === String(groupId));
    if (!group) return false;
    return group.role.rank >= parseInt(minRank, 10);
  } catch {
    return true;
  }
}

// Routes
app.get("/", requireLogin, async (req, res) => {
  const { id, username, avatar, theme } = req.cookies;
  const wsRes = await dbQuery('SELECT * FROM "existing workspaces";', []);
  const workspaces = wsRes.rows || [];
  const allowed = [];
  for (const ws of workspaces) {
    if (!ws.rblx_group_id || !ws.min_rank_id || isNaN(ws.min_rank_id)) {
      allowed.push(ws);
      continue;
    }
    if (await robloxGroupRankCheck(id, ws.rblx_group_id, ws.min_rank_id)) allowed.push(ws);
  }
  res.render("index", {
    user: username,
    userProfileURL: avatar,
    theme: theme || "n/a",
    workspaces: allowed.map(ws => ({
      id: ws.id,
      name: ws.workspace_name,
      image: ws.workspace_img_url,
      groupId: ws.rblx_group_id || null
    }))
  });
});

app.get("/workspace/:id", requireLogin, csrfProtection, async (req, res) => {
  const workspaceId = req.params.id;
  const wsRes = await dbQuery('SELECT * FROM "existing workspaces" WHERE id=$1 LIMIT 1;', [workspaceId]);
  const ws = wsRes.rows[0];
  if (!ws) return res.status(404).send("Workspace not found");

  const { id: robloxId, username, avatar } = req.cookies;
  if (ws.rblx_group_id && ws.min_rank_id) {
    const ok = await robloxGroupRankCheck(robloxId, ws.rblx_group_id, ws.min_rank_id);
    if (!ok) return res.render("notallowed", { user: username, userProfileURL: avatar, redirectUrl: "/", csrfToken: req.csrfToken() });
  }

  res.render("workspacehome", { user: username, userProfileURL: avatar, workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url }, csrfToken: req.csrfToken() });
});

app.get("/logout", (req, res) => {
  clearLoginCookies(res);
  req.session.destroy(() => res.redirect("https://keylogroup.co.uk/auth/roblox"));
});

// Start
app.listen(PORT, "0.0.0.0", () => console.log("Workspace server running on port", PORT));
