// server.js - Backend for ZeroPoint Dashboard

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios'); // For making HTTP requests to Discord API
const path = require('path');
const pg = require('pg'); // PostgreSQL client
const pgSession = require('connect-pg-simple')(session); // PostgreSQL session store
const { Client } = pg; // Destructure Client from pg (though Pool is used for sessions, Client can be used for direct queries)

// Load environment variables from .env file
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000; // Use process.env.PORT or default to 3000

// --- PostgreSQL Setup for Sessions and Guild Settings ---
const DATABASE_URL = process.env.DATABASE_URL; // PostgreSQL connection URL

if (!DATABASE_URL) {
    console.error("CRITICAL ERROR: DATABASE_URL environment variable is not set. Database operations will fail.");
    process.exit(1); // Exit if database URL is mandatory
}

// PostgreSQL client pool configuration
const pgPoolConfig = {
    connectionString: DATABASE_URL,
    // For production, you might need SSL options depending on your hosting provider
    // ssl: {
    //     rejectUnauthorized: false // Use this if you have issues with self-signed certs in development/testing
    // }
};

const pgPool = new pg.Pool(pgPoolConfig);

// Optional: Log successful connection or errors
pgPool.on('connect', () => console.log('✅ PostgreSQL client connected successfully!'));
pgPool.on('error', (err) => console.error('❌ PostgreSQL Pool Error', err.message, err.stack));

/**
 * Initializes the database by checking if the 'guild_settings' table exists.
 * If not, it creates the table with the required schema.
 * It also ensures the 'user_sessions' table (for connect-pg-simple) is correctly set up.
 */
async function initDatabase() {
    try {
        console.log("[INFO] Checking for 'user_sessions' table existence...");
        // Check and create user_sessions table (managed by connect-pg-simple, but good to ensure)
        await pgPool.query(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                sid VARCHAR(255) NOT NULL PRIMARY KEY,
                sess JSONB NOT NULL,
                expire TIMESTAMP WITH TIME ZONE NOT NULL
            );
        `);
        console.log("✅ 'user_sessions' table ensured.");

        console.log("[INFO] Checking for 'guild_settings' table existence...");
        const res = await pgPool.query(`
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_name = 'guild_settings'
            );
        `);

        if (!res.rows[0].exists) {
            console.log("[INFO] 'guild_settings' table not found. Creating table...");
            await pgPool.query(`
                CREATE TABLE guild_settings (
                    guild_id VARCHAR(255) PRIMARY KEY,
                    settings_data JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            `);
            console.log("✅ 'guild_settings' table created successfully!");
        } else {
            console.log("✅ 'guild_settings' table already exists.");
        }
    } catch (error) {
        console.error("❌ Database initialization failed:", error.message);
        process.exit(1); // Exit if database initialization fails
    }
}

// Function to provide default settings for a new guild
function getDefaultGuildSettings() {
    return {
        general: { botPrefix: '!', defaultRole: '' },
        welcome: { welcomeChannel: '', farewellChannel: '', welcomeMessage: `Welcome {user} to the server!`, farewellMessage: `{user} has left the server.`, sendWelcomeDM: false },
        logging: { logChannel: '', logMessages: true, logChannels: true, logMembers: true },
        ticket: { ticketCategory: '', ticketRole: '', ticketMessage: 'Hello {user}! How can we help you today?' },
        verification: {
            channelId: '', unverifiedRoleId: '', verifiedRoleId: '',
            messageContent: 'Welcome {user}! To gain access to the server, please click the "Verify" button below.',
            embed: {
                title: '✅ Server Verification',
                description: 'Please click the button below to verify your account and gain full access to the server. This helps us keep our community safe!',
                color: '#2cb4e9', footer: { text: 'ZeroPoint | Verification' }, thumbnail: { url: 'https://melonvisuals.me/test/zeropoint.png' }
            }
        },
        customCommands: [], // Array of { name: 'cmd', response: 'text', type: 'text' | 'embed', embed: {...} }
        reactionRoles: [],  // Array of { channelId: 'id', messageContent: 'msg', emoji: '👍', roleId: 'id' }
        leveling: { xpPerMessage: 15, xpCooldown: 60, levelUpMessage: 'Congratulations {user}, you reached level {level}!', levelUpChannel: '', rewards: [] }, // rewards: [{ level: 10, roleId: 'id' }]
        music: { musicChannel: '', djRoleId: '', allowAnyoneQueue: true },
        integrations: { webhookUrl: '', webhookChannelId: '' },
        advanced: { commandCooldown: 3, enableAI: false, adminRoleId: '' },
        // Mock analytics and audit log data, will be generated dynamically if not in DB
        analytics: {
            totalMembers: Math.floor(Math.random() * 5000) + 100,
            messages24h: Math.floor(Math.random() * 10000) + 500,
            newMembers7d: Math.floor(Math.random() * 200) + 10,
            labels: Array.from({length: 7}, (_, i) => {
                const d = new Date();
                d.setDate(d.getDate() - (6 - i));
                return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            }),
            memberGrowthData: Array.from({length: 7}, () => Math.floor(Math.random() * 50) + 5),
            messageActivityData: Array.from({length: 7}, () => Math.floor(Math.random() * 1000) + 100)
        },
        auditLog: [
            { user: 'AdminUser#1234', type: 'MEMBER_KICK', description: 'Kicked troublesome user', timestamp: new Date(Date.now() - 3600000).toISOString() },
            { user: 'ModBot', type: 'MESSAGE_DELETE', description: 'Deleted spam message in #general', timestamp: new Date(Date.now() - 7200000).toISOString() },
            { user: 'User#5678', type: 'CHANNEL_CREATE', description: 'Created #new-channel', timestamp: new Date(Date.now() - 10800000).toISOString() },
            { user: 'AdminUser#1234', type: 'ROLE_UPDATE', description: 'Updated permissions for @Member role', timestamp: new Date(Date.now() - 14400000).toISOString() }
        ]
    };
}

/**
 * Fetches guild settings from PostgreSQL. If not found, returns default settings.
 * @param {string} guildId
 * @returns {Promise<Object>} Guild settings object
 */
async function getGuildSettingsFromDb(guildId) {
    try {
        const res = await pgPool.query('SELECT settings_data FROM guild_settings WHERE guild_id = $1', [guildId]);
        if (res.rows.length > 0) {
            return res.rows[0].settings_data;
        }
        // If not found, return default settings
        console.log(`[INFO] No settings found for guild ${guildId}. Returning default settings.`);
        return getDefaultGuildSettings();
    } catch (err) {
        console.error(`Error fetching guild settings for ${guildId} from DB:`, err);
        // Fallback to default settings in case of DB error
        return getDefaultGuildSettings();
    }
}

/**
 * Saves or updates guild settings in PostgreSQL.
 * @param {string} guildId
 * @param {Object} settings
 */
async function saveGuildSettingsToDb(guildId, settings) {
    try {
        await pgPool.query(
            'INSERT INTO guild_settings (guild_id, settings_data, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT (guild_id) DO UPDATE SET settings_data = EXCLUDED.settings_data, updated_at = CURRENT_TIMESTAMP',
            [guildId, settings]
        );
        console.log(`[INFO] Settings for guild ${guildId} saved to DB.`);
    } catch (err) {
        console.error(`Error saving guild settings for ${guildId} to DB:`, err);
        throw new Error('Failed to save settings to database.');
    }
}

// --- Discord OAuth2 Configuration ---
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://dashboard.melonvisuals.me/auth/discord/callback';
const SESSION_SECRET = process.env.SESSION_SECRET || 'c4j9K!pZ@x7sQ_rVf8tYuB$eN%wX&aC*dF+gH-jK=lLmN~oP:qRsT<uV>wX?yZ[0123456789]{|}~'; // IMPORTANT: Use a strong secret from .env
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; // Bot token for fetching bot's guilds

if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error("Error: DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET environment variables must be set.");
    process.exit(1);
}
if (SESSION_SECRET === 'c4j9K!pZ@x7sQ_rVf8tYuB$eN%wX&aC*dF+gH-jK=lLmN~oP:qRsT<uV>wX?yZ[0123456789]{|}~') {
    console.warn("WARNING: SESSION_SECRET is using a fallback value. Please set SESSION_SECRET in your .env file and Coolify environment variables for production.");
}
if (!DISCORD_BOT_TOKEN) {
    console.warn("WARNING: DISCORD_BOT_TOKEN is not set. Bot guild fetching and announcement features will not work.");
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

// Helper function to log route registration
function registerRoute(method, path, ...handlers) {
    console.log(`[DEBUG] Registering route: ${method.toUpperCase()} ${path}`);
    app[method](path, ...handlers);
}

// Call database initialization before setting up session middleware and routes
initDatabase().then(() => {
    app.use(session({
        store: new pgSession({
            pool : pgPool,
            tableName : 'user_sessions',
            // pgSession automatically handles 'expire' as TIMESTAMP WITH TIME ZONE
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
    console.log(`[DEBUG] Session cookie 'secure' setting applied: ${process.env.NODE_ENV === 'production' || REDIRECT_URI.startsWith('https://')}`);

    app.use(passport.initialize());
    app.use(passport.session());

    app.use(express.json()); // JSON body parser for POST requests
    app.use(express.static(path.join(__dirname, 'public'))); // Serve static files

    // Middleware to check if user is authenticated
    function checkAuthenticated(req, res, next) {
        console.log(`[DEBUG] checkAuthenticated: Path: ${req.path}, SessionID: ${req.sessionID}`);
        console.log(`[DEBUG] checkAuthenticated: req.isAuthenticated() = ${req.isAuthenticated()}`);

        if (req.isAuthenticated()) {
            console.log("[DEBUG] checkAuthenticated: User is authenticated. User ID:", req.user ? req.user.id : 'N/A');
            return next();
        }

        // If not authenticated, check if it's an API request
        if (req.path.startsWith('/api/')) {
            console.log("[DEBUG] checkAuthenticated: API request not authenticated. Sending 401 JSON.");
            return res.status(401).json({ message: 'Unauthorized: Please log in.' });
        } else {
            console.log("[DEBUG] checkAuthenticated: Non-API request not authenticated. Redirecting to /.");
            return res.redirect('/');
        }
    }

    // --- Routes ---
    registerRoute('get', '/login', (req, res, next) => {
        console.log("[DEBUG] /login: Initiating Discord OAuth.");
        passport.authenticate('discord')(req, res, next);
    });

    registerRoute('get', '/auth/discord/callback',
        passport.authenticate('discord', { failureRedirect: '/' }),
        (req, res) => {
            console.log("[DEBUG] OAuth2 Callback Success. isAuthenticated:", req.isAuthenticated());
            if (req.isAuthenticated()) {
                console.log("[DEBUG] OAuth2 Callback: User authenticated, redirecting to /dashboard.");
                res.redirect('/dashboard');
            } else {
                console.error("[ERROR] OAuth2 Callback: User not authenticated after successful Passport auth. This should not happen.");
                res.redirect('/');
            }
        }
    );

    registerRoute('get', '/dashboard', checkAuthenticated, (req, res) => {
        console.log("[DEBUG] Accessing /dashboard. isAuthenticated:", req.isAuthenticated());
        res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    });

    registerRoute('get', '/user', checkAuthenticated, (req, res) => {
        console.log("[DEBUG] Accessing /user. isAuthenticated:", req.isAuthenticated());
        console.log("[DEBUG] /user: Sending user data for ID:", req.user ? req.user.id : 'N/A');
        res.json(req.user);
    });

    registerRoute('get', '/bot-guilds', checkAuthenticated, async (req, res) => {
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

    // --- API ENDPOINTS FOR GUILD SETTINGS (PostgreSQL Integrated) ---

    registerRoute('get', '/api/guild-settings/:guildId', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        try {
            const settings = await getGuildSettingsFromDb(guildId);
            res.json(settings);
        } catch (error) {
            console.error(`Error in GET /api/guild-settings/${guildId}:`, error);
            res.status(500).json({ message: 'Failed to retrieve guild settings.' });
        }
    });

    registerRoute('post', '/api/guild-settings/:guildId/:settingType', checkAuthenticated, async (req, res) => {
        const { guildId, settingType } = req.params;
        const newSettings = req.body;

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            // Ensure the settingType exists or initialize it if it's a new category
            if (typeof currentSettings[settingType] === 'object' && currentSettings[settingType] !== null && !Array.isArray(currentSettings[settingType])) {
                currentSettings[settingType] = {
                    ...currentSettings[settingType], // Keep existing sub-settings
                    ...newSettings // Apply new settings
                };
            } else {
                // If the settingType was previously undefined or not an object, assign directly
                currentSettings[settingType] = newSettings;
            }

            await saveGuildSettingsToDb(guildId, currentSettings);
            console.log(`[INFO] Updated ${settingType} settings for guild ${guildId}.`);
            res.status(200).json({ message: `${settingType} settings updated successfully.` });
        } catch (error) {
            console.error(`Error in POST /api/guild-settings/${guildId}/${settingType}:`, error);
            res.status(500).json({ message: `Failed to save ${settingType} settings.`, error: error.message });
        }
    });

    // --- Custom Commands API ---
    registerRoute('post', '/api/guild-settings/:guildId/custom-commands', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        const newCommand = req.body;

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.customCommands) {
                currentSettings.customCommands = [];
            }

            // Basic validation
            if (!newCommand.name || !newCommand.response) {
                return res.status(400).json({ message: 'Command name and response are required.' });
            }

            // Check for duplicate command name
            if (currentSettings.customCommands.some(cmd => cmd.name === newCommand.name)) {
                return res.status(409).json({ message: `Command '${newCommand.name}' already exists.` });
            }

            currentSettings.customCommands.push(newCommand);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Added custom command to guild ${guildId}:`, newCommand.name);
            res.status(201).json({ message: 'Custom command added successfully.', command: newCommand });
        } catch (error) {
            console.error(`Error in POST /api/guild-settings/${guildId}/custom-commands:`, error);
            res.status(500).json({ message: 'Failed to add custom command.', error: error.message });
        }
    });

    registerRoute('delete', '/api/guild-settings/:guildId/custom-commands/:index', checkAuthenticated, async (req, res) => {
        const { guildId, index } = req.params;
        const cmdIndex = parseInt(index, 10);

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.customCommands) {
                return res.status(404).json({ message: 'No custom commands found for this guild.' });
            }

            if (isNaN(cmdIndex) || cmdIndex < 0 || cmdIndex >= currentSettings.customCommands.length) {
                return res.status(400).json({ message: 'Invalid command index.' });
            }

            const deletedCommand = currentSettings.customCommands.splice(cmdIndex, 1);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Deleted custom command from guild ${guildId}:`, deletedCommand[0].name);
            res.status(200).json({ message: 'Custom command deleted successfully.', command: deletedCommand[0] });
        } catch (error) {
            console.error(`Error in DELETE /api/guild-settings/${guildId}/custom-commands/${index}:`, error);
            res.status(500).json({ message: 'Failed to delete custom command.', error: error.message });
        }
    });

    // --- Reaction Roles API ---
    registerRoute('post', '/api/guild-settings/:guildId/reaction-roles', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        const newReactionRole = req.body;

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.reactionRoles) {
                currentSettings.reactionRoles = [];
            }

            // Basic validation
            if (!newReactionRole.channelId || !newReactionRole.messageContent || !newReactionRole.emoji || !newReactionRole.roleId) {
                return res.status(400).json({ message: 'All fields are required for a reaction role.' });
            }

            currentSettings.reactionRoles.push(newReactionRole);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Added reaction role to guild ${guildId}:`, newReactionRole.emoji);
            res.status(201).json({ message: 'Reaction role added successfully.', reactionRole: newReactionRole });
        } catch (error) {
            console.error(`Error in POST /api/guild-settings/${guildId}/reaction-roles:`, error);
            res.status(500).json({ message: 'Failed to add reaction role.', error: error.message });
        }
    });

    registerRoute('delete', '/api/guild-settings/:guildId/reaction-roles/:index', checkAuthenticated, async (req, res) => {
        const { guildId, index } = req.params;
        const rrIndex = parseInt(index, 10);

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.reactionRoles) {
                return res.status(404).json({ message: 'No reaction roles found for this guild.' });
            }

            if (isNaN(rrIndex) || rrIndex < 0 || rrIndex >= currentSettings.reactionRoles.length) {
                return res.status(400).json({ message: 'Invalid reaction role index.' });
            }

            const deletedReactionRole = currentSettings.reactionRoles.splice(rrIndex, 1);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Deleted reaction role from guild ${guildId}:`, deletedReactionRole[0].emoji);
            res.status(200).json({ message: 'Reaction role deleted successfully.', reactionRole: deletedReactionRole[0] });
        } catch (error) {
            console.error(`Error in DELETE /api/guild-settings/${guildId}/reaction-roles/${index}:`, error);
            res.status(500).json({ message: 'Failed to delete reaction role.', error: error.message });
        }
    });

    // --- Leveling Rewards API ---
    registerRoute('post', '/api/guild-settings/:guildId/leveling-rewards', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        const newReward = req.body;

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.leveling) {
                currentSettings.leveling = getDefaultGuildSettings().leveling; // Ensure leveling object exists
            }
            if (!currentSettings.leveling.rewards) {
                currentSettings.leveling.rewards = [];
            }

            // Basic validation
            if (isNaN(newReward.level) || newReward.level <= 0 || !newReward.roleId) {
                return res.status(400).json({ message: 'Valid level and role ID are required for a level reward.' });
            }

            // Check for duplicate level
            if (currentSettings.leveling.rewards.some(reward => reward.level === newReward.level)) {
                return res.status(409).json({ message: `A reward for level ${newReward.level} already exists.` });
            }

            currentSettings.leveling.rewards.push(newReward);
            // Sort rewards by level for consistent display
            currentSettings.leveling.rewards.sort((a, b) => a.level - b.level);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Added level reward to guild ${guildId}: Level ${newReward.level}`);
            res.status(201).json({ message: 'Level reward added successfully.', reward: newReward });
        } catch (error) {
            console.error(`Error in POST /api/guild-settings/${guildId}/leveling-rewards:`, error);
            res.status(500).json({ message: 'Failed to add level reward.', error: error.message });
        }
    });

    registerRoute('delete', '/api/guild-settings/:guildId/leveling-rewards/:index', checkAuthenticated, async (req, res) => {
        const { guildId, index } = req.params;
        const rewardIndex = parseInt(index, 10);

        try {
            const currentSettings = await getGuildSettingsFromDb(guildId);
            if (!currentSettings.leveling || !currentSettings.leveling.rewards) {
                return res.status(404).json({ message: 'No leveling rewards found for this guild.' });
            }

            if (isNaN(rewardIndex) || rewardIndex < 0 || rewardIndex >= currentSettings.leveling.rewards.length) {
                return res.status(400).json({ message: 'Invalid level reward index.' });
            }

            const deletedReward = currentSettings.leveling.rewards.splice(rewardIndex, 1);
            await saveGuildSettingsToDb(guildId, currentSettings);

            console.log(`[INFO] Deleted level reward from guild ${guildId}: Level ${deletedReward[0].level}`);
            res.status(200).json({ message: 'Level reward deleted successfully.', reward: deletedReward[0] });
        } catch (error) {
            console.error(`Error in DELETE /api/guild-settings/${guildId}/leveling-rewards/${index}:`, error);
            res.status(500).json({ message: 'Failed to delete level reward.', error: error.message });
        }
    });

    // --- Analytics API ---
    registerRoute('get', '/api/analytics/:guildId', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        try {
            const settings = await getGuildSettingsFromDb(guildId);
            // Return the analytics data from settings (which will be default/mock if not in DB)
            res.json(settings.analytics);
        } catch (error) {
            console.error(`Error in GET /api/analytics/${guildId}:`, error);
            res.status(500).json({ message: 'Failed to retrieve analytics data.' });
        }
    });

    // --- Audit Log API ---
    registerRoute('get', '/api/audit-log/:guildId', checkAuthenticated, async (req, res) => {
        const { guildId } = req.params;
        try {
            const settings = await getGuildSettingsFromDb(guildId);
            // Return the audit log data from settings (which will be default/mock if not in DB)
            res.json(settings.auditLog);
        } catch (error) {
            console.error(`Error in GET /api/audit-log/${guildId}:`, error);
            res.status(500).json({ message: 'Failed to retrieve audit log data.' });
        }
    });

    // --- Announcement API ---
    registerRoute('post', '/api/send-announcement/:guildId', checkAuthenticated, async (req, res) => {
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

    registerRoute('get', '/logout', (req, res) => {
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

    registerRoute('get', '/', (req, res) => {
        console.log("[DEBUG] Accessing / (login page). isAuthenticated:", req.isAuthenticated());
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });

    // Catch-all route for any other requests that don't match, redirect to index.html
    // This should be the very last route defined.
    registerRoute('get', '*', (req, res) => {
        console.log(`[DEBUG] Catch-all route for: ${req.path}. Redirecting to /.`);
        res.redirect('/');
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
}).catch(err => {
    console.error("❌ Failed to initialize database and start application:", err);
    process.exit(1);
});
