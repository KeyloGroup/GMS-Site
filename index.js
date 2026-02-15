const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const { createClient } = require("redis");
const RedisStore = require("connect-redis").default;
const csurf = require("csurf");
const crypto = require("crypto");
const axios = require("axios");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const querystring = require("querystring");

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
  "REDIS_URL"
].forEach(v=>{
  if(!process.env[v]){ console.error(`Missing ${v}`); process.exit(1); }
});

const userdataPool = new Pool({ connectionString: process.env.PG_URL_USERDATA });

const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect().catch(console.error);

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex");

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new RedisStore({ client: redisClient }),
  name: "keylo.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none",
    domain: ".keyloroblox.xyz",
    maxAge: 30*24*60*60*1000
  }
}));

const csrfProtection = csurf({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "none",
    domain: ".keyloroblox.xyz",
    path: "/"
  }
});

app.set("views", path.join(__dirname,"views"));
app.set("view engine","ejs");
app.use(express.static(path.join(__dirname,"public")));

function setLoginCookies(res, { id, username, avatar }){
  const base = { secure:true, sameSite:"none", httpOnly:false, domain:".keyloroblox.xyz", path:"/", maxAge:30*24*60*60*1000 };
  res.cookie("id", String(id), base);
  res.cookie("username", String(username), base);
  res.cookie("avatar", String(avatar), base);
}

function clearLoginCookies(res){
  const base = { secure:true, sameSite:"none", httpOnly:false, domain:".keyloroblox.xyz", path:"/" };
  ["id","username","avatar","theme"].forEach(c=>res.clearCookie(c,base));
}

app.get("/", (req,res)=>{
  return res.render("index", { title: "Keylo" });
});

app.get("/auth/roblox", (req,res)=>{
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;
  req.session.save(()=>{
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

app.get("/auth/roblox/callback", async (req,res)=>{
  try{
    const { code, state, error, error_description } = req.query;
    if(error) return res.status(400).send(error_description||error);
    if(!code || !state || !req.session.oauthState || state!==req.session.oauthState) return res.status(400).send("Invalid OAuth session");

    const tokenRes = await axios.post("https://apis.roblox.com/oauth/v1/token",
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

    const banned = await userdataPool.query('SELECT * FROM "AccountsBan" WHERE username=$1 LIMIT 1',[robloxUsername]);
    if(banned.rows.length>0){
      return res.redirect(`https://app.keyloroblox.xyz/account/restricted?reason=${encodeURIComponent(banned.rows[0].reason||"Restricted")}`);
    }

    const users = await userdataPool.query('SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1',[robloxUsername]);
    clearLoginCookies(res);
    setLoginCookies(res,{ id: robloxId, username: robloxUsername, avatar: avatarUrl });

    if(users.rows.length>0){
      req.session.oauthState=null;
      req.session.loggedIn=true; // prevent OAuth loops
      return req.session.save(()=>res.redirect("https://app.keyloroblox.xyz/"));
    }

    req.session.pendingRoblox = { robloxId, robloxUsername, avatarUrl };
    return res.redirect("/register?oauth=success");

  }catch(err){
    console.error(err);
    clearLoginCookies(res);
    return res.status(500).send("OAuth failed");
  }
});

app.get("/register", csrfProtection, (req,res)=>{
  const pending = req.session.pendingRoblox;
  if(req.query.oauth==="success" && pending){
    return res.render("passwordregister",{
      title: "Keylo - Complete Registration",
      csrfToken: req.csrfToken(),
      robloxUsername: pending.robloxUsername,
      avatarUrl: pending.avatarUrl
    });
  }
  return res.render("register",{ title:"Keylo - Register", csrfToken:req.csrfToken() });
});

app.post("/api/register", csrfProtection, async (req,res)=>{
  try{
    const pending = req.session.pendingRoblox;
    if(!pending) return res.status(400).send("Missing OAuth session");

    const { password } = req.body;
    if(!password || password.length<6) return res.status(400).send("Password too short");

    const hashedPassword = await bcrypt.hash(password,12);
    await userdataPool.query(
      'INSERT INTO "Accounts" ("roblox username","hashed password") VALUES ($1,$2)',
      [pending.robloxUsername, hashedPassword]
    );

    req.session.pendingRoblox=null;
    req.session.loggedIn=true;
    return res.redirect("https://app.keyloroblox.xyz/");

  }catch(err){
    console.error(err);
    return res.status(500).send("Registration failed");
  }
});

app.get("/login", csrfProtection, (req,res)=>{
  res.render("login",{
    csrfToken: req.csrfToken(),
    oauthSuccess: req.query.oauth==="success",
    robloxUsername: req.query.username||"",
    robloxId: req.query.id||""
  });
});

app.post("/login", csrfProtection, async (req,res)=>{
  try{
    const { robloxUsername, password } = req.body;
    if(!robloxUsername || !password) return res.status(400).send("Missing credentials");

    const users = await userdataPool.query(
      'SELECT * FROM "Accounts" WHERE "roblox username"=$1 LIMIT 1',[robloxUsername]
    );

    if(!users.rows.length) return res.status(401).send("User not found");

    const match = await bcrypt.compare(password, users.rows[0]["hashed password"]);
    if(!match) return res.status(401).send("Invalid password");

    req.session.loggedIn=true;
    return req.session.save(()=>res.redirect("https://app.keyloroblox.xyz/"));

  }catch(err){
    console.error(err);
    return res.status(500).send("Login failed");
  }
});

app.get("/logout",(req,res)=>{
  clearLoginCookies(res);
  req.session.destroy(()=>res.redirect("/"));
});

app.use((req,res)=>res.status(404).render("404"));

app.listen(PORT,()=>console.log(`keyloroblox.xyz running on port ${PORT}`));
