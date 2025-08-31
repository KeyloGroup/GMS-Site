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

dotenv.config();

const app = express();
const PORT = 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(csurf({ cookie: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

// -------------------- MAILCOW TRANSPORT --------------------
const transporter = nodemailer.createTransport({
    host: process.env.MAILCOW_HOST || "mail.keyloroblox.xyz",
    port: 465, // use 465 for SSL, 587 for STARTTLS
    secure: true, // true = SSL
    auth: {
        user: process.env.MAILCOW_USER || "noreply@keyloroblox.xyz",
        pass: process.env.MAILCOW_PASS
    }
});

// -------------------- ROUTES --------------------
app.get('/', (req, res) => {
    res.render('index', { title: "Keylo" });
});

app.get('/waitlist', (req, res) => {
    res.render('waitlist', { 
        title: "Keylo - Waitlist",
        csrfToken: req.csrfToken()
    });
});

app.post('/waitlist', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.includes('@')) {
            return res.status(400).send("Invalid email");
        }

        const { error } = await supabase
            .from('waitlist_emails')
            .insert([{ email }]);

        if (error) {
            console.error("❌ Supabase insert error:", error);
            return res.status(500).send("Database error");
        }

        await transporter.sendMail({
          from: `"Keylo" <${process.env.MAILCOW_USER}>`,
          to: email,
          subject: "Welcome to the Keylo Waitlist 🎉",
          html:  `
          <h2 style="font-family:Arial, sans-serif; color:#333; margin-bottom:16px;">
          Welcome to the Keylo Waitlist 🎉
          </h2>
          
          <p style="font-family:Arial, sans-serif; font-size:15px; color:#555; line-height:1.6;">
          Hi there 👋,
          </p>

          <p style="font-family:Arial, sans-serif; font-size:15px; color:#555; line-height:1.6;">
          Thank you for joining the <strong>Keylo</strong> waitlist! You’re now officially on our early access list. 
          We’ll keep you updated with exciting news and send your exclusive invite as soon as we launch.
          </p>

          <p style="font-family:Arial, sans-serif; font-size:15px; color:#555; line-height:1.6;">
          We’re thrilled to have you with us and can’t wait to share what’s coming next 🚀.
          </p>

          <hr style="border:none; border-top:1px solid #eee; margin:24px 0;" />

          <p style="font-family:Arial, sans-serif; font-size:14px; color:#777; line-height:1.6;">
          If you have any questions or need support, feel free to reach us at 
          <a href="mailto:support@keyloroblox.xyz" style="color:#1a73e8; text-decoration:none;">
          support@keyloroblox.co.uk
          </a>.
          </p>

          <b>Regards,</b>

          <p style="font-family:Arial, sans-serif; font-size:15px; color:#555; margin-top:16px;">
          The Keylo Team
          </p>

          <p style="font-family:Arial, sans-serif; font-size:14px; color:#777;">
          E: support@keyloroblox.xyz <br />
          Discord: <a href="https://discord.gg/t8Yr2u58Xg" style="color:#1a73e8; text-decoration:none;">Join here</a>
          </p>

          <hr style="border:none; border-top:1px solid #eee; margin:24px 0;" />

          <p style="font-family:Arial, sans-serif; font-size:12px; color:#999; line-height:1.4;">
          This email and any attachments are confidential and may contain private information intended solely for the use of the individual recipient. 
          If you have received this email by mistake, please immediately notify the support team at 
          <a href="mailto:support@keyloroblox.xyz" style="color:#1a73e8; text-decoration:none;">support@keyloroblox.xyz</a>.
          </p>

          <p style="font-family:Arial, sans-serif; font-size:12px; color:#999; line-height:1.4;">
          We may also use the emails you send for employee training. If you do not want your email to be used for training, please let us know immediately.
          </p>
          `
        });

        res.render('waitlist', { 
            title: "Keylo - Waitlist",
            csrfToken: req.csrfToken(),
            success: true
        });

    } catch (err) {
        console.error(err);
        res.render('waitlist', { 
            title: "Keylo - Waitlist",
            csrfToken: req.csrfToken(),
            error: "Something went wrong. Please try again later."
        });
    }
});

app.get('/launch', (req, res) => {
    res.render('launch', {
        title: "Keylo - Launch",
        user: "test",
    });
});

// -------------------- ROBLOX HELPERS --------------------
const EMOJIS = ['😀', '🎮', '🌟', '🚀', '🐱', '🔥', '🎲', '💎', '🛡️', '⚔️'];

function generateEmojiCode(len = 5) {
    return Array.from({ length: len }, () =>
        EMOJIS[Math.floor(Math.random() * EMOJIS.length)]
    ).join('');
}

app.get('/api/roblox/user/:id', async (req, res, next) => {
    try {
        const { id } = req.params;
        const profileRes = await axios.get(`https://users.roblox.com/v1/users/${id}`);
        if (!profileRes.data || !profileRes.data.name) throw new Error('User not found');

        const thumbRes = await axios.get(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${id}&size=150x150&format=Png&isCircular=true`
        );

        const avatarUrl = thumbRes.data.data[0]?.imageUrl || null;

        res.json({
            id,
            name: profileRes.data.name,
            avatar: avatarUrl
        });
    } catch (err) {
        next(err);
    }
});

app.get('/api/register/get/robloxusername/:id', async (req, res, next) => {
    try {
        const { id } = req.params;
        const profileRes = await axios.get(`https://users.roblox.com/v1/users/${id}`);
        if (!profileRes.data || !profileRes.data.name) throw new Error('User not found');

        res.json({ success: true, username: profileRes.data.name });
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

        const thumbRes = await axios.get(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${id}&size=150x150&format=Png&isCircular=true`
        );

        const avatarUrl = thumbRes.data.data[0]?.imageUrl || null;

        if (profile.description && profile.description.includes(code)) {
            res.json({
                success: true,
                id,
                name: profile.name,
                avatar: avatarUrl
            });
        } else {
            throw new Error('Code not found in bio');
        }
    } catch (err) {
        next(err);
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { robloxUsername, password } = req.body;

        if (!robloxUsername || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const lookupRes = await axios.post(
            'https://users.roblox.com/v1/usernames/users',
            {
                usernames: [robloxUsername],
                excludeBannedUsers: false
            },
            { headers: { 'Content-Type': 'application/json' } }
        );

        if (!lookupRes.data?.data?.length) {
            return res.status(404).json({ error: 'Roblox user not found' });
        }

        const robloxId = lookupRes.data.data[0].id;

        // TODO: Save to Supabase instead of MySQL
        let groupRank = 'Member';
        try {
            const groupInfo = await axios.get(`https://groups.roblox.com/v2/users/${robloxId}/groups/roles`);
            const targetGroup = groupInfo.data.data.find(g => g.group.id === 65844213);
            if (targetGroup) groupRank = targetGroup.role.name;
        } catch (err) {
            console.warn('Group rank fetch failed:', err.message);
        }

        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

        // TODO: Insert into Supabase users table (future)
        req.session.userId = robloxId; // temp session
        res.redirect('/workspace');
    } catch (err) {
        console.error('❌ Registration error:', err);
        res.status(500).send('Server error during registration');
    }
});

// ------------------- START SERVER ------------------- //
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});
