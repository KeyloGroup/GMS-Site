// server.js
// Combined + updated to cookie-based auth for user identity

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const dotenv = require('dotenv');
const crypto = require('crypto');
const axios = require('axios');
const session = require('express-session');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const { version } = require('os');

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Keylo API",
      version: "1.0.0",
      description: "A documentation to all public Keylo API endpoints",
    },
    servers: [
      {
        url: "https://keyloroblox.xyz",
      },
    ],
  },
  apis: [__filename],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

dotenv.config();
const app = express();
const PORT = 3000;

/* -------------------- SUPABASE -------------------- */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const supabaseAccounts = createClient(
  process.env.SUPABASE_ACCOUNTS_URL,
  process.env.SUPABASE_ACCOUNTS_SERVICE_ROLE_KEY
);
const supabaseWorkspaces = createClient(
  process.env.SUPABASE_WORKSPACES_URL,
  process.env.SUPABASE_WORKSPACES_SERVICE_ROLE_KEY
);

/* -------------------- MIDDLEWARE -------------------- */
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Keep session only for ephemeral things (e.g., emoji verification code)
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 30,
    },
  })
);

app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(csurf({ cookie: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

/* -------------------- MAIL TRANSPORTS -------------------- */
const transporter = nodemailer.createTransport({
  host: process.env.MAILCOW_HOST || 'mail.keyloroblox.xyz',
  port: 465,
  secure: true,
  auth: {
    user: process.env.MAILCOW_USER || 'noreply@keyloroblox.xyz',
    pass: process.env.MAILCOW_PASS,
  },
});

const recruitmentTransporter = nodemailer.createTransport({
  host: process.env.RECRUITMENT_MAIL_HOST || 'mail.keyloroblox.xyz',
  port: 465,
  secure: true,
  auth: {
    user: process.env.RECRUITMENT_MAIL_USER || 'recruitment@keyloroblox.xyz',
    pass: process.env.RECRUITMENT_MAIL_PASS,
  },
});

/* -------------------- HELPERS -------------------- */
function setUserCookies(res, userData) {
  const cookieOptions = {
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    httpOnly: false, // allow client to read username/avatar/theme
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  };
  res.cookie('user_id', userData.id, cookieOptions);
  res.cookie('username', userData.username, cookieOptions);
  res.cookie('profile_pic', userData.avatar, cookieOptions);
  res.cookie('theme', userData.theme || 'n/a', cookieOptions);
}

async function fetchRobloxUsernameById(userId) {
  const profileRes = await axios.get(`https://users.roblox.com/v1/users/${userId}`);
  return profileRes.data?.name || 'Guest';
}

async function getAvatarUrl(userId) {
  const thumbRes = await axios.get(
    `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=true`
  );
  return thumbRes.data?.data?.[0]?.imageUrl || '/images/default-avatar.png';
}

/* -------------------- APPLY ROUTE -------------------- */
app.post('/apply', async (req, res) => {
  try {
    const { role, roblox, discord, email, age, why, experience } = req.body;
    if (!role || !roblox || !discord || !email || !age || !why) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const mailOptions = {
      from: '"Keylo Recruitment" <recruitment@keyloroblox.xyz>',
      to: 'recruitment@keyloroblox.xyz',
      subject: `Application for ${role}`,
      html: `
        <h2>New Application for ${role}</h2>
        <p><strong>Roblox Username:</strong> ${roblox}</p>
        <p><strong>Discord Username:</strong> ${discord}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Age:</strong> ${age}</p>
        <p><strong>Why they want to work here:</strong> ${why}</p>
        <p><strong>Previous experience / portfolio:</strong> ${experience || 'N/A'}</p>
      `,
    };

    await recruitmentTransporter.sendMail(mailOptions);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Error sending recruitment email:', err);
    res.status(500).json({ error: 'Failed to send application' });
  }
});

/* -------------------- BASIC ROUTES -------------------- */
app.get('/', (req, res) => {
  res.render('index', { title: 'Keylo' });
});


app.get('/register', (req, res) => {
  res.render('register', { title: 'Keylo - Register', csrfToken: req.csrfToken() });
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Keylo - Login', csrfToken: req.csrfToken() });
});

/* -------------------- REGISTER -------------------- */
app.post('/api/register', async (req, res) => {
  try {
    const { robloxUsername, password } = req.body;
    if (!robloxUsername || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const lookupRes = await axios.post(
      'https://users.roblox.com/v1/usernames/users',
      { usernames: [robloxUsername], excludeBannedUsers: false },
      { headers: { 'Content-Type': 'application/json' } }
    );
    if (!lookupRes.data?.data?.length) {
      return res.status(404).json({ error: 'Roblox user not found' });
    }

    const robloxId = lookupRes.data.data[0].id;
    const hashedPassword = await bcrypt.hash(password, 12);

    const { error } = await supabaseAccounts
      .from('Accounts')
      .insert([{ 'roblox username': robloxUsername, 'hashed password': hashedPassword }]);

    if (error) {
      console.error('❌ Supabase Accounts insert error:', error);
      return res.status(500).json({ error: 'Database insert failed' });
    }

    const avatarUrl = await getAvatarUrl(robloxId);
    setUserCookies(res, { id: robloxId, username: robloxUsername, avatar: avatarUrl, theme: 'n/a' });

    res.redirect('/launch');
  } catch (err) {
    console.error('❌ Registration error:', err);
    res.status(500).send('Server error during registration');
  }
});

/* -------------------- LOGIN -------------------- */
app.post('/login', async (req, res) => {
  try {
    const { robloxUsername, password } = req.body;
    if (!robloxUsername || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }

    const { data: users, error } = await supabaseAccounts
      .from('Accounts')
      .select('*')
      .eq('roblox username', robloxUsername)
      .limit(1);

    if (error) {
      console.error('❌ Supabase query error:', error);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!users || users.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user['hashed password']);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const lookupRes = await axios.post(
      'https://users.roblox.com/v1/usernames/users',
      { usernames: [user['roblox username']], excludeBannedUsers: false },
      { headers: { 'Content-Type': 'application/json' } }
    );
    const robloxId = lookupRes.data?.data?.[0]?.id;

    const avatarUrl = await getAvatarUrl(robloxId);
    setUserCookies(res, { id: robloxId, username: user['roblox username'], avatar: avatarUrl, theme: 'n/a' });

    res.redirect('/launch');
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).send('Server error during login');
  }
});

/* -------------------- LAUNCH -------------------- */
app.get('/launch', (req, res) => {
  if (!req.cookies.user_id) return res.redirect('/login');
  res.render('launch', {
    user: req.cookies.username || 'Guest',
    userProfileURL: req.cookies.profile_pic || '/images/default-avatar.png',
    csrfToken: req.csrfToken(),
  });
});

/* -------------------- LOGOUT -------------------- */
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.clearCookie('user_id');
    res.clearCookie('username');
    res.clearCookie('profile_pic');
    res.clearCookie('theme');
    res.redirect('/login');
  });
});

/* -------------------- ROBLOX HELPERS -------------------- */
const EMOJIS = ['😀', '🎮', '🌟', '🚀', '🐱', '🔥', '🎲', '💎', '🛡️', '⚔️'];
function generateEmojiCode(len = 5) {
  return Array.from({ length: len }, () => EMOJIS[Math.floor(Math.random() * EMOJIS.length)]).join('');
}

/**
 * @swagger
 * /api/roblox/user/{id}:
 * get:
 * summary: Get roblox user info
 * description: Fetch roblox username and avatr by ID
 * parameters:
 * - in: path
 * name: id
 * required: true
 * schema:
 * type: string
 * description: Roblox user ID
 * responses:
 * 200:
 * description: User info retrieved successfully
 * content:
 * application/json:
 * schema:
 * type: object
 * properties:
 * id:
 * type: string
 * name:
 * type: string
 * avtar:
 * type: string
 * 404:
 * description: User not found
 */
app.get('/api/roblox/user/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const name = await fetchRobloxUsernameById(id);
    const avatarUrl = await getAvatarUrl(id);
    res.json({ id, name, avatar: avatarUrl });
  } catch (err) {
    next(err);
  }
});

app.get('/api/register/get/robloxusername/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const name = await fetchRobloxUsernameById(id);
    res.json({ success: true, username: name });
  } catch (err) {
    next(err);
  }
});

app.get('/api/roblox/code', (req, res) => {
  const code = generateEmojiCode();
  req.session.verificationCode = code;
  req.session.codeGeneratedAt = Date.now();
  res.json({ code });
});

app.get('/api/roblox/check-bio/:id/:code', async (req, res, next) => {
  try {
    const { id, code } = req.params;

    if (!req.session.verificationCode || Date.now() - req.session.codeGeneratedAt > 5 * 60 * 1000) {
      throw new Error('Code expired');
    }
    if (req.session.verificationCode !== code) {
      throw new Error('Invalid code');
    }

    const profileRes = await axios.get(`https://users.roblox.com/v1/users/${id}`);
    const profile = profileRes.data;
    const avatarUrl = await getAvatarUrl(id);

    if (profile.description && profile.description.includes(code)) {
      res.json({ success: true, id, name: profile.name, avatar: avatarUrl });
    } else {
      throw new Error('Code not found in bio');
    }
  } catch (err) {
    next(err);
  }
});

/* -------------------- WORKSPACES ROUTES -------------------- */

// Single workspace home
app.get('/workspace/:id', async (req, res) => {
  try {
    if (!req.cookies.user_id) {
      return res.redirect('/login');
    }
    const workspaceId = req.params.id;

    const { data: ws, error } = await supabaseWorkspaces
      .from('existing workspaces')
      .select('*')
      .eq('id', workspaceId)
      .single();

    if (error || !ws) {
      console.error('❌ Workspace not found:', error);
      return res.status(404).send('Workspace not found');
    }

    const robloxId = req.cookies.user_id;
    const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
    const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));

    res.render('workspacehome', {
      user: username,
      userProfileURL: avatarUrl,
      workspace: {
        id: ws.id,
        name: ws.workspace_name,
        image: ws.workspace_img_url,
      },
      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('❌ Error loading workspace:', err);
    res.status(500).send('Server error');
  }
});

// Workspaces list (with optional group rank filter as in old code)
app.get('/workspaces', async (req, res) => {
  try {
    if (!req.cookies.user_id) {
      return res.redirect('/login');
    }

    const robloxId = req.cookies.user_id;
    const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
    const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));


    //Make it so it makes more tables in supabase following format of worksapceid_activity, workspaceid_sessions, worksapceid_tasks, worksapceid_settings and worksapceid_logbook
    const { data: workspaces, error } = await supabaseWorkspaces
      .from('existing workspaces')
      .select('*');

    if (error) {
      console.error('❌ Supabase Workspaces fetch error:', error);
      return res.render('workspaces', {
        user: username,
        userProfileURL: avatarUrl,
        csrfToken: req.csrfToken(),
        workspaces: [],
      });
    }

    const allowedWorkspaces = [];
    for (let ws of workspaces) {
      if (!ws.rblx_group_id || !ws.min_rank_id) {
        allowedWorkspaces.push(ws);
        continue;
      }
      try {
        const rankRes = await axios.get(
          `https://groups.roblox.com/v2/users/${robloxId}/groups/roles`
        );
        const groupInfo = rankRes.data?.data?.find((g) => g.group.id == ws.rblx_group_id);
        if (groupInfo && groupInfo.role.rank >= parseInt(ws.min_rank_id, 10)) {
          allowedWorkspaces.push(ws);
        }
      } catch (err) {
        console.warn(`⚠️ Could not check group rank for ws ${ws.id}: ${err.message}`);
      }
    }

    res.render('workspaces', {
      user: username,
      userProfileURL: avatarUrl,
      csrfToken: req.csrfToken(),
      workspaces: allowedWorkspaces.map((ws) => ({
        id: ws.id,
        name: ws.workspace_name,
        image: ws.workspace_img_url,
      })),
    });
  } catch (err) {
    console.error('❌ Workspaces load error:', err);
    res.render('workspaces', {
      user: 'Guest',
      userProfileURL: '/images/default-avatar.png',
      csrfToken: req.csrfToken(),
      workspaces: [],
    });
  }
});

// Create workspace
app.post('/workspace/create', async (req, res) => {
  try {
    if (!req.cookies.user_id) return res.status(401).json({ error: 'Not logged in' });

    const { name, image, groupId, minRank } = req.body;
    if (!name) return res.status(400).json({ error: 'Workspace name is required' });

    const ownerUsername =
      req.cookies.username || (await fetchRobloxUsernameById(req.cookies.user_id));

    const { error } = await supabaseWorkspaces.from('existing workspaces').insert([
      {
        workspace_name: name,
        owner_username: ownerUsername,
        workspace_img_url: image || null,
        rblx_group_id: groupId || null,
        min_rank_id: minRank || null,
      },
    ]);

    if (error) {
      console.error('❌ Supabase Workspaces insert error:', error);
      return res.json({ success: false, error: 'Database insert failed' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Workspace create error:', err);
    res.json({ success: false, error: 'Server error' });
  }
});

/* -------------------- SESSIONS PAGE (DUMMY DATA) -------------------- */
app.get('/workspace/:id/sessions', async (req, res) => {
  try {
    if (!req.cookies.user_id) {
      return res.redirect('/login');
    }
    const workspaceId = req.params.id;

    const { data: ws, error } = await supabaseWorkspaces
      .from('existing workspaces')
      .select('*')
      .eq('id', workspaceId)
      .single();

    if (error || !ws) {
      console.error('❌ Workspace not found:', error);
      return res.status(404).send('Workspace not found');
    }

    const robloxId = req.cookies.user_id;
    const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
    const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));

    // Dummy sessions for now
    const sessions = [
      {
        id: 's1',
        title: 'Basic Training',
        timeFormatted: '10:00 AM - 11:00 AM',
        host: { name: 'Alice', avatar: 'https://ui-avatars.com/api/?name=Alice' },
        coHost: { name: 'Bob' },
        groups: ['Supervisors', 'Spectators'],
        type: 'Training',
      },
      {
        id: 's2',
        title: 'Shift Session',
        timeFormatted: '2:00 PM - 4:00 PM',
        host: { name: 'Charlie', avatar: 'https://ui-avatars.com/api/?name=Charlie' },
        coHost: null,
        groups: [],
        type: 'Shift',
      },
    ];

    // Example date buttons
    const days = [
      { label: 'Mon', active: false },
      { label: 'Tue', active: false },
      { label: 'Wed', active: true },
      { label: 'Thu', active: false },
      { label: 'Fri', active: false },
    ];

    res.render('sessions', {
      user: username,
      userProfileURL: avatarUrl,
      workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url },
      sessions,
      days,
      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('❌ Error loading sessions:', err);
    res.status(500).send('Server error');
  }
});

/* -------------------- WORKSPACE SETTINGS -------------------- */
app.get('/workspace/:id/settings', async (req, res) => {
  try {
    if (!req.cookies.user_id) return res.redirect('/login');

    const workspaceId = req.params.id;
    const { data: ws, error } = await supabaseWorkspaces
      .from('existing workspaces')
      .select('*')
      .eq('id', workspaceId)
      .single();

    if (error || !ws) {
      return res.status(404).send('Workspace not found');
    }

    const robloxId = req.cookies.user_id;
    const username = req.cookies.username || (await fetchRobloxUsernameById(robloxId));
    const avatarUrl = req.cookies.profile_pic || (await getAvatarUrl(robloxId));

    res.render('workspacesettings', {
      user: username,
      userProfileURL: avatarUrl,
      workspace: { id: ws.id, name: ws.workspace_name, image: ws.workspace_img_url },
      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    console.error('❌ Error loading settings:', err);
    res.status(500).send('Server error');
  }
});

/* -------------------- Actvity Endpoints -------------------- */

app.get('/api/activity/entry/new/', async (req, res) => {
  const worksapceid = req.params.Worksapce_ID;
  const apikey_auth = req.params.API_Key;
  const targetUser = req.params.User_ID;
  const totaltime_tracked = req.params.Tracked_Time;
  const type = req.params.Type;
};

/* -------------------- Session Endpoints -------------------- */

app.get('/api/sessions/list', async (req, res) => {
  const worksapceid = req.params.Workspace_ID;
  const apikey_auth = req.params.API_Key;
  const type = req.params.Type;
  const timeframe = req.params.type // Either day or week
  
};

app.get('/api/sessions/create', async (req, res) => {
  const workspaceid = req.params.Workspace_ID;
  const apikey_auth = req.params.API_Key;
  const type = req.params.Type;
  const host = req.params.Type;
  const co_host = req.params.Co_Host;
  const StartTime = req.params.Start_Time;
  const durationTime = req.Params.Duraion;
  const assisantGroups = req.Params.Groups;
  const date = req.Params.Session_Date;
  
};

app.get('/api/sessions/delete', async (req, res) => {
  const workspaceid = req.params.Workspace_ID;
  const apikey_auth = req.headers.authentication.API_Key;
  const sessionsid = req.params.Session_ID;
  
};

app.get('/api/sessions/update/attendies', async (req, res) => {};

/* -------------------- ERROR HANDLER -------------------- */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (req.accepts('json')) {
    return res.status(500).json({ error: err.message || 'Server error' });
  }
  res.status(500).send('Server error');
});

/* -------------------- START SERVER -------------------- */
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
