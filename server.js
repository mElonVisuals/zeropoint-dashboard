// server.js
// Backend server for the ZeroPoint Bot Dashboard

require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const axios = require('axios'); // Import axios for making HTTP requests

// --- Redis Session Store Setup ---
// Import Redis and connect-redis
const redis = require('redis');
const RedisStore = require('connect-redis').default; // Use .default for commonJS import

const app = express();
// Explicitly set PORT to 3000 for consistency with Dockerfile EXPOSE
// and to avoid issues if process.env.PORT is not set by the environment.
const PORT = 3000;

// --- Discord OAuth2 Configuration ---
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://dashboard.melonvisuals.me/auth/discord/callback';
const SESSION_SECRET = process.env.SESSION_SECRET || 'c4j9K!pZ@x7sQ_rVf8tYuB$eN%wX&aC*dF+gH-jK=lLmN~oP:qRsT<uV>wX?yZ[0123456789]{|}~'; // IMPORTANT: Use a strong secret from .env
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; // NEW: Bot token for fetching bot's guilds
const REDIS_URL = process.env.REDIS_URL; // NEW: Redis connection URL

if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error("Error: DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET environment variables must be set.");
    process.exit(1);
}
if (SESSION_SECRET === 'a_fallback_secret_if_not_set_in_env') {
    console.warn("WARNING: SESSION_SECRET is using a fallback value. Please set SESSION_SECRET in your .env file and Coolify environment variables for production.");
}
if (!DISCORD_BOT_TOKEN) {
    console.warn("WARNING: DISCORD_BOT_TOKEN is not set. Bot guild fetching and announcement features will not work.");
}
if (!REDIS_URL) {
    console.error("CRITICAL ERROR: REDIS_URL environment variable is not set. Session persistence will fail without it.");
    // In a real production app, you might want to exit here if Redis is mandatory
    // process.exit(1);
}

// Log NODE_ENV to help with debugging production vs. development behavior
console.log(`[DEBUG] NODE_ENV is: ${process.env.NODE_ENV}`);
// Log a masked version of the session secret to confirm it's being picked up
console.log(`[DEBUG] SESSION_SECRET (masked): ${SESSION_SECRET.substring(0, 5)}...${SESSION_SECRET.substring(SESSION_SECRET.length - 5)}`);


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.
//   Typically, this will be as simple as storing the user ID when serializing
//   and finding the user by ID when deserializing.
passport.serializeUser((user, done) => {
    // Note: req.sessionID is not directly available here, but the session is managed by express-session
    console.log("[DEBUG] serializeUser: User ID", user.id);
    done(null, user);
});

passport.deserializeUser((obj, done) => {
    // This log is critical to see what Passport is trying to deserialize
    console.log("[DEBUG] deserializeUser: Object received for deserialization:", obj);
    if (obj && obj.id) {
        console.log("[DEBUG] deserializeUser: User ID", obj.id); // Log when user is deserialized
        done(null, obj);
    } else {
        console.error("[ERROR] deserializeUser: Invalid user object received. Session might be corrupted or missing user data.");
        // If obj is undefined/null, it means the session data stored by serializeUser was lost.
        // This is the common symptom of using MemoryStore in production.
        done(new Error("Invalid user object or session data lost"), null);
    }
});

// Use the DiscordStrategy within Passport.
passport.use(new DiscordStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: REDIRECT_URI,
    scope: ['identify', 'guilds'] // Request user ID, username, and guilds they are in
},
(accessToken, refreshToken, profile, done) => {
    // In this example, we're just passing the profile directly.
    // In a real application, you'd save/find the user in your database here.
    console.log("[DEBUG] DiscordStrategy Callback: User Profile ID", profile.id);
    // Removed: profile.sessionID = this.sessionID; // This was problematic
    return done(null, profile);
}));

// --- Express Middleware ---

// Initialize Redis client options
const redisClientOptions = {
    url: REDIS_URL,
};

// Conditionally add TLS options if the REDIS_URL indicates a secure connection
if (REDIS_URL && REDIS_URL.startsWith('rediss://')) {
    redisClientOptions.tls = {
        rejectUnauthorized: false // WARNING: Use this only if you trust the Redis server and its network.
                                  // In production with a public Redis, you'd typically use a CA certificate.
    };
    console.log("[DEBUG] Redis client configured for TLS with rejectUnauthorized: false.");
} else {
    console.log("[DEBUG] Redis client configured for non-TLS connection (or REDIS_URL not set/invalid).");
}

const redisClient = redis.createClient(redisClientOptions);

redisClient.on('connect', () => console.log('✅ Redis client connected successfully!'));
redisClient.on('error', (err) => console.error('❌ Redis Client Error', err));

// Connect to Redis
redisClient.connect().catch(console.error); // Ensure connect() is called

app.use(session({
    store: new RedisStore({ client: redisClient }), // Use RedisStore
    secret: SESSION_SECRET, // Use the secret from environment variables
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
        maxAge: 60000 * 60 * 24, // Session lasts 24 hours
        // Set 'secure' to true if the REDIRECT_URI starts with HTTPS,
        // or if NODE_ENV is 'production' (Coolify often sets this).
        secure: process.env.NODE_ENV === 'production' || REDIRECT_URI.startsWith('https://'),
        httpOnly: true, // Prevents client-side JavaScript from accessing cookies
        sameSite: 'Lax' // Recommended for security and modern browser behavior
    }
}));
// Add this line right after the session middleware setup
console.log(`[DEBUG] Session cookie 'secure' setting applied: ${app.get('env') === 'production' || REDIRECT_URI.startsWith('https://')}`);


app.use(passport.initialize());
app.use(passport.session());

// Enable JSON body parsing for incoming requests
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
    console.log(`[DEBUG] ensureAuthenticated: Path: ${req.path}, SessionID: ${req.sessionID}`); // Log session ID here
    // This log will show if the passport object is even present in the session
    console.log(`[DEBUG] ensureAuthenticated: req.session.passport =`, req.session.passport);
    console.log(`[DEBUG] ensureAuthenticated: req.isAuthenticated() = ${req.isAuthenticated()}`);
    console.log(`[DEBUG] ensureAuthenticated: req.session =`, req.session); // Log the entire session object
    console.log(`[DEBUG] ensureAuthenticated: req.user =`, req.user); // Log the entire user object

    if (req.isAuthenticated()) {
        console.log("[DEBUG] ensureAuthenticated: User is authenticated. User ID:", req.user ? req.user.id : 'N/A');
        return next();
    }
    console.log("[DEBUG] ensureAuthenticated: User not authenticated for path:", req.path, "Redirecting to /");
    res.redirect('/');
}

// --- Routes ---

// Route to initiate Discord OAuth2 login
app.get('/login', (req, res, next) => {
    console.log("[DEBUG] /login: Initiating Discord OAuth.");
    passport.authenticate('discord')(req, res, next);
});

// OAuth2 callback route
app.get('/auth/discord/callback',
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => {
        console.log("[DEBUG] OAuth2 Callback Success. isAuthenticated:", req.isAuthenticated());
        // After successful authentication, the user object is attached to req.session.passport.user
        // We can now log the session ID here to compare with deserializeUser
        console.log("[DEBUG] OAuth2 Callback: Session ID after auth:", req.sessionID);
        if (req.isAuthenticated()) {
            console.log("[DEBUG] OAuth2 Callback: User authenticated, redirecting to /dashboard.");
            res.redirect('/dashboard');
        } else {
            console.error("[ERROR] OAuth2 Callback: User not authenticated after successful Passport auth. This should not happen.");
            res.redirect('/'); // Should not happen if Passport auth was successful
        }
    }
);

// Dashboard route - requires authentication
app.get('/dashboard', ensureAuthenticated, (req, res) => { // Added ensureAuthenticated middleware
    console.log("[DEBUG] Accessing /dashboard. isAuthenticated:", req.isAuthenticated());
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// User data endpoint (protected)
app.get('/user', ensureAuthenticated, (req, res) => { // Added ensureAuthenticated middleware
    console.log("[DEBUG] Accessing /user. isAuthenticated:", req.isAuthenticated());
    console.log("[DEBUG] /user: Sending user data for ID:", req.user ? req.user.id : 'N/A');
    res.json(req.user); // req.user contains the Discord profile
});

// NEW: Endpoint to get guilds the bot is in (protected)
app.get('/bot-guilds', ensureAuthenticated, async (req, res) => {
    console.log("[DEBUG] Accessing /bot-guilds. isAuthenticated:", req.isAuthenticated());
    if (!DISCORD_BOT_TOKEN) {
        console.error("[ERROR] /bot-guilds: DISCORD_BOT_TOKEN is not set in environment variables.");
        return res.status(500).json({ message: "Bot token not configured on the server." });
    }

    try {
        // Fetch guilds the bot is in using Discord API
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

// NEW: Endpoint to handle saving advanced settings (placeholder for now)
app.post('/api/settings/advanced/:guildId', ensureAuthenticated, (req, res) => {
    const { guildId } = req.params;
    const settings = req.body;
    console.log(`[DEBUG] Received advanced settings for guild ${guildId}:`, settings);
    // In a real application, you would save these settings to a database
    res.status(200).json({ message: `Advanced settings for guild ${guildId} saved successfully (simulated).` });
});

// NEW: Endpoint to send an embedded message as the bot for announcements
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
            // Optionally, you can include content for a regular message alongside the embed
            // content: "New Announcement!"
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


// Logout route
app.get('/logout', (req, res) => {
    console.log("[DEBUG] /logout: Attempting logout for user:", req.user ? req.user.id : 'N/A');
    req.logout((err) => { // req.logout requires a callback in newer Passport versions
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

// Default route (serves the login page)
app.get('/', (req, res) => {
    console.log("[DEBUG] Accessing / (login page). isAuthenticated:", req.isAuthenticated());
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
// Added a try-catch block around app.listen for better error reporting during startup
try {
    app.listen(PORT, () => {
        console.log(`ZeroPoint Dashboard backend running on http://localhost:${PORT}`);
        console.log(`Discord OAuth2 Redirect URI: ${REDIRECT_URI}`);
        // Log the actual secure setting based on the REDIRECT_URI
        console.log(`Session cookie 'secure' setting (based on REDIRECT_URI): ${REDIRECT_URI.startsWith('https://')}`);
    });
} catch (startupError) {
    console.error("[CRITICAL ERROR] Failed to start Express server:", startupError.message);
    // You might want to exit the process here if the server cannot start
    process.exit(1);
}
