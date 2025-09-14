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
const { Client } = require('pg');
const { parseISO, startOfDay, endOfDay, addDays } = require("date-fns");

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

const pgClient = new Client({
    connectionString: process.env.SUPABASE_PG_URL
});

pgClient.connect((err) => {
    if (err) {
        console.error('❌ Failed to connect to Supabase PostgreSQL database:', err.stack);
    } else {
        console.log('✅ Connected to Supabase PostgreSQL database.');
    }
});

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

function getClosestDateForWeekday(targetDayIndex) {
    const today = new Date();
    const todayIndex = today.getDay(); // 0=Sun … 6=Sat
    let diff = targetDayIndex - todayIndex;
    if (diff < 0) diff += 7;
    const date = new Date(today);
    date.setDate(today.getDate() + diff);
    return date.toISOString().split('T')[0]; // YYYY-MM-DD
}

async function getAvatarUrl(userId) {
    try {
        const thumbRes = await axios.get(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=true`
        );
        return thumbRes.data?.data?.[0]?.imageUrl || '/images/default-avatar.png';
    } catch {
        return '/images/default-avatar.png';
    }
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
 *   get:
 *     summary: Get Roblox user info
 *     description: Fetch Roblox username and avatar by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: Roblox user ID
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: User info retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 name:
 *                   type: string
 *                 avatar:
 *                   type: string
 *       '404':
 *         description: User not found
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

async function generateUniqueWorkspaceId() {
    let id;
    let exists = true;

    while (exists) {
        id = Math.floor(Math.random() * 1000000); // e.g., 6-digit random number
        const { data, error } = await supabaseWorkspaces
            .from('existing workspaces')
            .select('id')
            .eq('id', id)
            .limit(1);

        if (error) {
            throw new Error('Error checking workspace ID uniqueness: ' + error.message);
        }

        exists = data.length > 0;
    }

    return id;
}

app.post('/workspace/create', async (req, res) => {
    try {
        if (!req.cookies.user_id) return res.status(401).json({ error: 'Not logged in' });

        const { name, image, groupId, minRank } = req.body;
        if (!name) return res.status(400).json({ error: 'Workspace name is required' });
        if (!image) return res.status(400).json({ error: 'Workspace icon image URL is required' });
        if (!groupId) return res.status(400).json({ error: 'Workspace group id is required' });
        if (!minRank) return res.status(400).json({ error: 'Workspace group minimum access rank is required' });

        const ownerUsername = req.cookies.username || (await fetchRobloxUsernameById(req.cookies.user_id));
        const newWorkspaceId = await generateUniqueWorkspaceId();

        const { data, error } = await supabaseWorkspaces.from('existing workspaces').insert([
            {
                workspace_name: name,
                id: newWorkspaceId,
                owner_username: ownerUsername,
                workspace_img_url: image || null,
                rblx_group_id: groupId || null,
                min_rank_id: minRank || null,
            },
        ]).select('id').single();

        if (error) {
            console.error('❌ Supabase Workspaces insert error:', error);
            return res.json({ success: false, error: 'Database insert failed' });
        }

        const sessionsTableName = `ws_sessions_${newWorkspaceId}`;
        const activityTableName = `ws_activity_${newWorkspaceId}`;
        const tasksTableName = `ws_tasks_${newWorkspaceId}`;
        const logbookTableName = `ws_logbook_${newWorkspaceId}`;
        const settingsTableName = `ws_settings_${newWorkspaceId}`;

        try {
            const createSessionsTableQuery = `
                CREATE TABLE IF NOT EXISTS ${sessionsTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    host_id BIGINT NOT NULL,
                    co_host_id BIGINT,
                    start_time TIMESTAMPTZ NOT NULL,
                    duration_minutes INTEGER,
                    groups JSONB,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createActivityTableQuery = `
                CREATE TABLE IF NOT EXISTS ${activityTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id BIGINT NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    tracked_time INTEGER NOT NULL,
                    total_time INTEGER NOT NULL,
                    average_time INTEGER NOT NULL,
                    session_id UUID REFERENCES ${sessionsTableName}(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createTasksTableQuery = `
                CREATE TABLE IF NOT EXISTS ${tasksTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    assigned_to BIGINT,
                    completed BOOLEAN DEFAULT FALSE,
                    assigned_by VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createLogbookTableQuery = `
                CREATE TABLE IF NOT EXISTS ${logbookTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    author BIGINT NOT NULL,
                    target_user_id BIGINT NOT NULL,
                    type VARCHAR(255) NOT NULL,
                    expiry_date TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;
            const createSettingsTableQuery = `
                CREATE TABLE IF NOT EXISTS ${settingsTableName} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    min_role_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    api_key TEXT NOT NULL,
                    flags BOOLEAN NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
            `;

            await pgClient.query(createSessionsTableQuery);
            await pgClient.query(createActivityTableQuery);
            await pgClient.query(createTasksTableQuery);
            await pgClient.query(createLogbookTableQuery);
            await pgClient.query(createSettingsTableQuery);

            console.log(`✅ All tables for new workspace '${newWorkspaceId}' created successfully.`);
        } catch (dbErr) {
            console.error(`❌ Error creating tables for workspace '${newWorkspaceId}':`, dbErr);
            return res.json({ success: false, error: 'Database table creation failed' });
        }

        res.json({ success: true, workspaceId: newWorkspaceId });
    } catch (err) {
        console.error('❌ Workspace create error:', err);
        res.json({ success: false, error: 'Server error' });
    }
});

/* -------------------- SESSIONS PAGE (REAL DATA) -------------------- */
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

        // query today's sessions by default
        const todayIndex = new Date().getDay();
        const targetDate = getClosestDateForWeekday(todayIndex);

        const tableName = `ws_sessions_${workspaceId}`;
        const query = `
            SELECT * FROM "${tableName}"
            WHERE DATE(start_time) = $1
            ORDER BY start_time ASC
        `;
        const { rows: sessions } = await pgClient.query(query, [targetDate]);

        // build weekday buttons
        const days = [
            { label: 'Sun', index: 0, active: todayIndex === 0 },
            { label: 'Mon', index: 1, active: todayIndex === 1 },
            { label: 'Tue', index: 2, active: todayIndex === 2 },
            { label: 'Wed', index: 3, active: todayIndex === 3 },
            { label: 'Thu', index: 4, active: todayIndex === 4 },
            { label: 'Fri', index: 5, active: todayIndex === 5 },
            { label: 'Sat', index: 6, active: todayIndex === 6 },
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

/* -------------------- Activity Endpoints -------------------- */

/**
 * @swagger
 * /api/activity/entry/new/{workspaceId}:
 *   post:
 *     summary: Add a new activity entry
 *     description: Records a user's tracked activity time in a specific workspace
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         description: The ID of the workspace
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               apiKey:
 *                 type: string
 *               userId:
 *                 type: integer
 *               trackedTime:
 *                 type: integer
 *               activityType:
 *                 type: string
 *               sessionId:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Activity entry created successfully
 *       '400':
 *         description: Invalid input or missing required fields
 *       '401':
 *         description: Unauthorized, invalid API key
 *       '500':
 *         description: Server error
 */


app.post('/api/activity/entry/new/:workspaceId', async (req, res) => {
    const { apiKey, userId, trackedTime, type, sessionId } = req.body;
    const workspaceId = req.params.workspaceId;
    // TODO: Implement API key authentication logic here
    // TODO: Implement database insert logic using the workspaceId to determine the table name
    res.status(200).json({ message: 'Activity entry created successfully.' });
});

/* -------------------- Session Endpoints -------------------- */

/**
 * @swagger
 * /api/sessions/list/{workspaceId}:
 *   get:
 *     summary: Get a list of sessions
 *     description: Retrieves sessions for a workspace, optionally filtered by type and timeframe
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: apiKey
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *         description: Filter by session type
 *       - in: query
 *         name: timeframe
 *         schema:
 *           type: string
 *           enum: [day, week, month]
 *         description: Filter by timeframe
 *     responses:
 *       '200':
 *         description: A list of sessions
 *       '401':
 *         description: Unauthorized
 *       '500':
 *         description: Server error
 */
app.get('/api/sessions/list/:workspaceId', async (req, res) => {
    const { type, timeframe } = req.query;
    const { workspaceId } = req.params;
    // TODO: Implement API key authentication and database query logic here
    res.status(200).json({ sessions: [] });
});

/**
 * @swagger
 * /api/sessions/{workspaceId}/create:
 *   post:
 *     summary: Create a new session
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               apiKey:
 *                 type: string
 *               type:
 *                 type: string
 *               title:
 *                 type: string
 *               hostId:
 *                 type: integer
 *               coHostId:
 *                 type: integer
 *               startTime:
 *                 type: string
 *                 format: date-time
 *               durationMinutes:
 *                 type: integer
 *               groups:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       '201':
 *         description: Session created successfully
 *       '400':
 *         description: Invalid input
 *       '401':
 *         description: Unauthorized
 *       '500':
 *         description: Server error
 */
app.post('/api/sessions/:workspaceId/create', async (req, res) => {
    const { apiKey, type, title, hostId, coHostId, startTime, durationMinutes, groups } = req.body;
    const workspaceId = req.params.workspaceId;
    // TODO: Implement API key authentication and database insert logic here
    res.status(201).json({ message: 'Session created successfully.' });
});

/**
 * @swagger
 * /api/sessions/delete/{workspaceId}/{sessionId}:
 *   delete:
 *     summary: Delete a session
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *       - in: header
 *         name: API_Key
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Session deleted successfully
 *       '401':
 *         description: Unauthorized
 *       '404':
 *         description: Session not found
 *       '500':
 *         description: Server error
 */
app.delete('/api/sessions/delete/:workspaceId/:sessionId', async (req, res) => {
    const { workspaceId, sessionId } = req.params;
    const apiKey = req.headers.authentication?.api_key || req.headers['api-key'];
    // TODO: Implement API key authentication and database delete logic here
    res.status(200).json({ message: 'Session deleted successfully.' });
});

/**
 * @swagger
 * /api/sessions/update/attendees/{workspaceId}/{sessionId}:
 *   post:
 *     summary: Update session attendees
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               apiKey:
 *                 type: string
 *               attendees:
 *                 type: array
 *                 items:
 *                   type: integer
 *     responses:
 *       '200':
 *         description: Attendees updated successfully
 *       '400':
 *         description: Invalid input
 *       '401':
 *         description: Unauthorized
 *       '404':
 *         description: Session not found
 *       '500':
 *         description: Server error
 */
app.post('/api/sessions/update/attendees/:workspaceId/:sessionId', async (req, res) => {
    const { attendees } = req.body;
    const { workspaceId, sessionId } = req.params;
    // TODO: Implement API key authentication and database update logic here
    res.status(200).json({ message: 'Attendees updated successfully.' });
});

// route: get sessions for a given workspace + weekday
app.get('/api/workspace/:id/sessions/day/:dayIndex', async (req, res) => {
    const { id, dayIndex } = req.params;
    const dayIdx = parseInt(dayIndex, 10);
    const workspaceId = parseInt(id, 10);
    if (isNaN(dayIdx) || isNaN(workspaceId) || dayIdx < 0 || dayIdx > 6) {
        return res.status(400).json({ error: 'Invalid parameters' });
    }
    const dateStr = getClosestDateForWeekday(dayIdx);
    const tableName = `ws_sessions_${workspaceId}`;
    try {
        const query = `
            SELECT * FROM "${tableName}"
            WHERE DATE(start_time) = $1
            ORDER BY start_time ASC
        `;
        const { rows } = await pgClient.query(query, [dateStr]);
        const sessions = rows.map(row => ({
            id: row.id,
            title: row.title,
            timeFormatted: row.start_time ? new Date(row.start_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
            isLive: false,
            type: row.type,
            host: {
                name: row.host_name || 'Unknown',
                avatar: row.host_avatar || '/icons/icons8-avatar-24.png',
            }
        }));
        res.json({ sessions });
    } catch (err) {
        console.error('Error fetching sessions by day:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * @swagger
 * /api/sessions/{workspaceId}/{sessionId}/server/create:
 *   post:
 *     summary: Create a server for a session
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               apiKey:
 *                 type: string
 *               serverType:
 *                 type: string
 *     responses:
 *       '201':
 *         description: Server created successfully
 *       '400':
 *         description: Invalid input
 *       '401':
 *         description: Unauthorized
 *       '500':
 *         description: Server error
 */
app.post('/api/sessions/:workspaceId/:sessionId/server/create', async (req, res) => {
    // TODO: Implement API key authentication and Roblox server creation logic here
    res.status(201).json({ message: 'Server created successfully.' });
});

/**
 * @swagger
 * /api/sessions/{workspaceId}/{sessionId}/server/delete:
 *   delete:
 *     summary: Delete a server for a session
 *     parameters:
 *       - in: path
 *         name: workspaceId
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: apiKey
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Server deleted successfully
 *       '401':
 *         description: Unauthorized
 *       '404':
 *         description: Server not found
 *       '500':
 *         description: Server error
 */
app.delete('/api/sessions/:workspaceId/:sessionId/server/delete', async (req, res) => {
    // TODO: Implement API key authentication and Roblox server deletion logic here
    res.status(200).json({ message: 'Server deleted successfully.' });
});

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
