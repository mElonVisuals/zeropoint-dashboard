// server.js
// Backend server for the ZeroPoint Bot Dashboard

require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const axios = require('axios'); // Import axios for making HTTP requests

// --- PostgreSQL Session Store Setup ---
const pg = require('pg'); // PostgreSQL client
const pgSession = require('connect-pg-simple')(session); // PostgreSQL session store

const app = express();
const PORT = 3000; // Explicitly set PORT to 3000

// --- Discord OAuth2 Configuration ---
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://dashboard.melonvisuals.me/auth/discord/callback';
const SESSION_SECRET = process.env.SESSION_SECRET || 'c4j9K!pZ@x7sQ_rVf8tYuB$eN%wX&aC*dF+gH-jK=lLmN~oP:qRsT<uV>wX?yZ[0123456789]{|}~'; // IMPORTANT: Use a strong secret from .env
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; // Bot token for fetching bot's guilds
const DATABASE_URL = process.env.DATABASE_URL; // NEW: PostgreSQL connection URL

if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error("Error: DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET environment variables must be set.");
    process.exit(1);
}
if (SESSION_SECRET === 'a_fallback_secret_if_not_set_in_env') { // This check is now less critical as a strong default is provided
    console.warn("WARNING: SESSION_SECRET is using a fallback value. Please set SESSION_SECRET in your .env file and Coolify environment variables for production.");
}
if (!DISCORD_BOT_TOKEN) {
    console.warn("WARNING: DISCORD_BOT_TOKEN is not set. Bot guild fetching and announcement features will not work.");
}
if (!DATABASE_URL) {
    console.error("CRITICAL ERROR: DATABASE_URL environment variable is not set. Session persistence will fail without it.");
    process.exit(1); // Exit if database URL is mandatory for session
}

// Log NODE_ENV to help with debugging production vs. development behavior
console.log(`[DEBUG] NODE_ENV is: ${process.env.NODE_ENV}`);
// Log a masked version of the session secret to confirm it's being picked up
console.log(`[DEBUG] SESSION_SECRET (masked): ${SESSION_SECRET.substring(0, 5)}...${SESSION_SECRET.substring(SESSION_SECRET.length - 5)}`);
// Log a masked version of the DATABASE_URL to confirm what the app is seeing
console.log(`[DEBUG] DATABASE_URL (masked): ${DATABASE_URL ? DATABASE_URL.substring(0, 10) + '...' + DATABASE_URL.substring(DATABASE_URL.length - 5) : 'Not Set'}`);


// Passport session setup.
passport.serializeUser((user, done) => {
    console.log("[DEBUG] serializeUser: User ID", user.id);
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    console.log("[DEBUG] deserializeUser: Object received for deserialization:", obj);
    if (obj && obj.id) {
        console.log("[DEBUG] deserializeUser: User ID", obj.id);
        done(null, obj);
    } else {
        console.error("[ERROR] deserializeUser: Invalid user object received. Session might be corrupted or missing user data.");
        done(new Error("Invalid user object or session data lost"), null);
    }
});

// Use the DiscordStrategy within Passport.
passport.use(new DiscordStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: REDIRECT_URI,
    scope: ['identify', 'guilds']
},
(accessToken, refreshToken, profile, done) => {
    console.log("[DEBUG] DiscordStrategy Callback: User Profile ID", profile.id);
    return done(null, profile);
}));

// --- Express Middleware ---

// CRITICAL FOR PROXY ENVIRONMENTS LIKE COOLIFY: Trust the proxy headers
app.set('trust proxy', 1);
console.log("[DEBUG] Express 'trust proxy' set to 1.");

// Initialize PostgreSQL client pool
const pgPoolConfig = {
    connectionString: DATABASE_URL,
};

// Removed the SSL configuration block.
// The error "The server does not support SSL connections" indicates
// that the PostgreSQL server is not configured for SSL, so we should not request it.
console.log("[DEBUG] PostgreSQL client configured for non-SSL connection (SSL options removed).");

// Log the final pgPoolConfig before creating the pool
console.log("[DEBUG] Final pgPoolConfig:", pgPoolConfig);


const pgPool = new pg.Pool(pgPoolConfig);

// Optional: Log successful connection or errors
pgPool.on('connect', () => console.log('✅ PostgreSQL client connected successfully!'));
pgPool.on('error', (err) => console.error('❌ PostgreSQL Pool Error', err.message, err.stack));

app.use(session({
    store: new pgSession({
        pool : pgPool,                // Connection pool
        tableName : 'user_sessions'   // Use a custom table name for sessions
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60000 * 60 * 24, // Session lasts 24 hours
        secure: process.env.NODE_ENV === 'production' || REDIRECT_URI.startsWith('https://'),
        httpOnly: true,
        sameSite: 'Lax'
    }
}));
console.log(`[DEBUG] Session cookie 'secure' setting applied: ${app.get('env') === 'production' || REDIRECT_URI.startsWith('https://')}`);

app.use(passport.initialize());
app.use(passport.session());

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
    console.log(`[DEBUG] ensureAuthenticated: Path: ${req.path}, SessionID: ${req.sessionID}`);
    console.log(`[DEBUG] ensureAuthenticated: req.session.passport =`, req.session.passport);
    console.log(`[DEBUG] ensureAuthenticated: req.isAuthenticated() = ${req.isAuthenticated()}`);
    console.log(`[DEBUG] ensureAuthenticated: req.session =`, req.session);
    console.log(`[DEBUG] ensureAuthenticated: req.user =`, req.user);

    if (req.isAuthenticated()) {
        console.log("[DEBUG] ensureAuthenticated: User is authenticated. User ID:", req.user ? req.user.id : 'N/A');
        return next();
    }
    console.log("[DEBUG] ensureAuthenticated: User not authenticated for path:", req.path, "Redirecting to /");
    res.redirect('/');
}

// --- Routes ---
app.get('/login', (req, res, next) => {
    console.log("[DEBUG] /login: Initiating Discord OAuth.");
    passport.authenticate('discord')(req, res, next);
});

app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        console.log("[DEBUG] OAuth2 Callback Success. isAuthenticated:", req.isAuthenticated());
        console.log("[DEBUG] OAuth2 Callback: Session ID after auth:", req.sessionID);
        if (req.isAuthenticated()) {
            console.log("[DEBUG] OAuth2 Callback: User authenticated, redirecting to /dashboard.");
            res.redirect('/dashboard');
        } else {
            console.error("[ERROR] OAuth2 Callback: User not authenticated after successful Passport auth. This should not happen.");
            res.redirect('/');
        }
    }
);

app.get('/dashboard', ensureAuthenticated, (req, res) => {
    console.log("[DEBUG] Accessing /dashboard. isAuthenticated:", req.isAuthenticated());
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/user', ensureAuthenticated, (req, res) => {
    console.log("[DEBUG] Accessing /user. isAuthenticated:", req.isAuthenticated());
    console.log("[DEBUG] /user: Sending user data for ID:", req.user ? req.user.id : 'N/A');
    res.json(req.user);
});

app.get('/bot-guilds', ensureAuthenticated, async (req, res) => {
    console.log("[DEBUG] Accessing /bot-guilds. isAuthenticated:", req.isAuthenticated());
    if (!DISCORD_BOT_TOKEN) {
        console.error("[ERROR] /bot-guilds: DISCORD_BOT_TOKEN is not set in environment variables.");
        return res.status(500).json({ message: "Bot token not configured on the server." });
    }

    try {
        const response = await axios.get('https://discord.com/api/v10/users/@me/guilds', {
            headers: {
                Authorization: `Bot ${DISCORD_BOT_TOKEN}`
            }
        });
        const botGuilds = response.data;
        console.log(`[DEBUG] /bot-guilds: Successfully fetched ${botGuilds.length} guilds for the bot.`);
        res.json(botGuilds);
    } catch (error) {
        console.error("[ERROR] Failed to fetch bot guilds from Discord API:", error.message);
        if (error.response) {
            console.error("Discord API response error data:", error.response.data);
            console.error("Discord API response status:", error.response.status);
        }
        res.status(500).json({ message: "Failed to fetch bot guilds." });
    }
});

app.post('/api/settings/advanced/:guildId', ensureAuthenticated, (req, res) => {
    const { guildId } = req.params;
    const settings = req.body;
    console.log(`[DEBUG] Received advanced settings for guild ${guildId}:`, settings);
    res.status(200).json({ message: `Advanced settings for guild ${guildId} saved successfully (simulated).` });
});

app.post('/api/send-announcement/:guildId', ensureAuthenticated, async (req, res) => {
    const { guildId } = req.params;
    const { channelId, embedData } = req.body;

    console.log(`[DEBUG] Attempting to send announcement for guild ${guildId} to channel ${channelId}.`);

    if (!DISCORD_BOT_TOKEN) {
        console.error("[ERROR] /api/send-announcement: DISCORD_BOT_TOKEN is not set.");
        return res.status(500).json({ message: "Bot token not configured on the server." });
    }
    if (!channelId || !embedData) {
        console.error("[ERROR] /api/send-announcement: Missing channelId or embedData in request body.");
        return res.status(400).json({ message: "Missing channelId or embedData." });
    }

    try {
        const discordApiUrl = `https://discord.com/api/v10/channels/${channelId}/messages`;
        const payload = {
            embeds: [embedData],
        };

        const response = await axios.post(discordApiUrl, payload, {
            headers: {
                'Authorization': `Bot ${DISCORD_BOT_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });

        console.log(`[DEBUG] Announcement sent successfully to channel ${channelId}. Discord API response status: ${response.status}`);
        res.status(200).json({ message: "Announcement sent successfully!", discordResponse: response.data });
    } catch (error) {
        console.error("[ERROR] Failed to send announcement via Discord API:", error.message);
        if (error.response) {
            console.error("Discord API response error data:", error.response.data);
            console.error("Discord API response status:", error.response.status);
        }
        res.status(500).json({ message: "Failed to send announcement.", error: error.message, discordApiError: error.response ? error.response.data : null });
    }
});

app.get('/logout', (req, res) => {
    console.log("[DEBUG] /logout: Attempting logout for user:", req.user ? req.user.id : 'N/A');
    req.logout((err) => {
        if (err) {
            console.error("Error during logout:", err);
            return res.status(500).send("Error during logout.");
        }
        req.session.destroy((err) => {
            if (err) {
                console.error("Error destroying session:", err);
                return res.status(500).send("Error destroying session.");
            }
            console.log("[DEBUG] Session destroyed. Redirecting to /.");
            res.redirect('/');
        });
    });
});

app.get('/', (req, res) => {
    console.log("[DEBUG] Accessing / (login page). isAuthenticated:", req.isAuthenticated());
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
try {
    app.listen(PORT, () => {
        console.log(`ZeroPoint Dashboard backend running on http://localhost:${PORT}`);
        console.log(`Discord OAuth2 Redirect URI: ${REDIRECT_URI}`);
        console.log(`Session cookie 'secure' setting (based on REDIRECT_URI): ${REDIRECT_URI.startsWith('https://')}`);
    });
} catch (startupError) {
    console.error("[CRITICAL ERROR] Failed to start Express server:", startupError.message);
    process.exit(1);
}
