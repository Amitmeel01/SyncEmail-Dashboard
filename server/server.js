const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const imaps = require('imap-simple');
const { simpleParser } = require('mailparser');
const dotenv = require('dotenv');
const { google } = require('googleapis');
const genericPool = require('generic-pool');
const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const tls = require('tls');

dotenv.config();

// --- CONFIGURATION ---
const app = express();
const port = process.env.PORT || 3001;
const mongoUri = process.env.MONGO_URI;

const oauth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL
);

// --- MIDDLEWARE ---
app.use(express.json());
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    next();
});

// --- DATABASE & GLOBALS ---
let db;
let mongoClient; // Keep a reference to the client for graceful shutdown
const syncJobs = {};
const connectionPools = new Map();

// --- HELPERS ---
const encrypt = (text) => Buffer.from(text).toString('base64');
const decrypt = (text) => Buffer.from(text, 'base64').toString('ascii');

const constructXOAuth2Token = (user, accessToken) => {
    const auth_string = `user=${user}\x01auth=Bearer ${accessToken}\x01\x01`;
    return Buffer.from(auth_string).toString('base64');
};

// --- ENHANCED IMAP CONNECTION POOL ---

async function refreshOAuth2Token(account) {
    if (!account.refreshToken) {
        throw new Error('No refresh token available. Re-authentication is required.');
    }
    try {
        console.log(`Refreshing OAuth2 token for ${account.user}`);
        oauth2Client.setCredentials({ refresh_token: account.refreshToken });

        const { credentials } = await oauth2Client.refreshAccessToken();
        account.accessToken = credentials.access_token;
        account.tokenExpiry = new Date(credentials.expiry_date);
        
        await db.collection('accounts').updateOne(
            { _id: account._id },
            { $set: { accessToken: account.accessToken, tokenExpiry: account.tokenExpiry } }
        );
        console.log(`✓ Token refreshed for ${account.user}`);
        return account;
    } catch (error) {
        console.error(`✗ Failed to refresh token for ${account.user}:`, error.response?.data || error.message);
        await db.collection('accounts').updateOne(
            { _id: account._id },
            { $set: { authStatus: 'invalid', lastError: 'Token refresh failed. Please re-authenticate.' } }
        );
        throw new Error('Token refresh failed.');
    }
}

function createPoolForAccount(account) {
    if (connectionPools.has(account._id.toString())) {
        return connectionPools.get(account._id.toString());
    }

    const factory = {
        create: async () => {
            console.log(`Creating connection for ${account.user}`);
            
            let currentAccount = { ...account };

            if (currentAccount.authType === 'XOAUTH2') {
                const now = new Date();
                const expiry = new Date(currentAccount.tokenExpiry);
                if (now >= new Date(expiry.getTime() - 5 * 60 * 1000)) {
                    currentAccount = await refreshOAuth2Token(currentAccount);
                }
            }

            const config = {
                imap: {
                    host: currentAccount.host,
                    port: currentAccount.port,
                    tls: true,
                    authTimeout: 25000,
                    connTimeout: 25000,
                    tlsOptions: { 
                        rejectUnauthorized: false,
                        servername: currentAccount.host
                    }
                }
            };

            if (currentAccount.authType === 'XOAUTH2') {
                config.imap.xoauth2 = constructXOAuth2Token(currentAccount.user, currentAccount.accessToken);
                config.imap.user = currentAccount.user;
            } else {
                config.imap.user = currentAccount.user;
                config.imap.password = decrypt(currentAccount.password);
            }

            try {
                const connection = await imaps.connect(config);
                console.log(`✓ Connection established for ${currentAccount.user}`);
                await db.collection('accounts').updateOne({ _id: currentAccount._id }, { $set: { authStatus: 'valid', lastError: null } });
                return connection;
            } catch (error) {
                console.error(`✗ Failed to create connection for ${currentAccount.user}:`, error.message);
                await db.collection('accounts').updateOne({ _id: currentAccount._id }, { $set: { authStatus: 'error', lastError: error.message } });
                throw error;
            }
        },
        destroy: (connection) => {
            if (connection && connection.state !== 'disconnected') {
                connection.end();
            }
        }
    };

    const pool = genericPool.createPool(factory, {
        min: 0,
        max: 3,
        acquireTimeoutMillis: 30000,
        createTimeoutMillis: 30000,
    });
    
    pool.on('factoryCreateError', (err) => {
        console.error(`Pool factory error for ${account.user}:`, err.message);
    });

    connectionPools.set(account._id.toString(), pool);
    return pool;
}

async function withConnection(accountId, callback) {
    const account = await db.collection('accounts').findOne({ _id: new ObjectId(accountId) });
    if (!account) throw new Error("Account not found");

    if (account.authStatus === 'invalid') {
        throw new Error(`Authentication for ${account.user} is invalid. Please re-authenticate.`);
    }

    const pool = createPoolForAccount(account);
    let connection;
    
    try {
        connection = await pool.acquire();
        return await callback(connection);
    } finally {
        if (connection) {
            await pool.release(connection);
        }
    }
}


// --- EMAIL ANALYTICS FUNCTIONS ---
async function detectESP(fromAddress, headers) {
    const domain = fromAddress.split('@')[1] || 'unknown.com';
    const espPatterns = { 'Gmail': ['gmail.com', 'googlemail.com'], 'Outlook': ['outlook.com', 'hotmail.com'], 'Yahoo': ['yahoo.com'], 'Amazon SES': ['amazonses.com'], 'SendGrid': ['sendgrid.net'] };
    for (const [esp, domains] of Object.entries(espPatterns)) { if (domains.some(d => domain.includes(d))) return esp; }
    const receivedHeaders = Array.isArray(headers.get('received')) ? headers.get('received') : [headers.get('received')];
    for (const received of receivedHeaders) { if (!received) continue; if (received.includes('gmail.com')) return 'Gmail'; if (received.includes('outlook.com')) return 'Outlook'; }
    return 'Unknown';
}

async function checkMailServerSecurity(domain) {
    try {
        const mxRecords = await dns.resolveMx(domain);
        if (!mxRecords || mxRecords.length === 0) return { hasValidMX: false, supportsTLS: false, hasValidCert: false };
        const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;
        const tlsResult = await new Promise((resolve) => {
            const socket = tls.connect({ port: 25, host: mxHost, rejectUnauthorized: false, timeout: 5000 });
            socket.on('secureConnect', () => { socket.end(); resolve({ supportsTLS: true, hasValidCert: socket.authorized }); });
            socket.on('error', () => resolve({ supportsTLS: false, hasValidCert: false }));
            socket.on('timeout', () => { socket.destroy(); resolve({ supportsTLS: false, hasValidCert: false }); });
        });
        return { hasValidMX: true, mxHost, ...tlsResult };
    } catch (error) {
        return { hasValidMX: false, supportsTLS: false, hasValidCert: false };
    }
}


// --- API ENDPOINTS ---
app.get('/api/auth/google', (req, res) => {
    const url = oauth2Client.generateAuthUrl({ access_type: 'offline', prompt: 'consent', scope: ['https://mail.google.com/'] });
    res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    const frontendUrl = process.env.FRONTEND_URL || "https://sync-email-dashboard.vercel.app/";
    try {
        if (!code) throw new Error('Authorization code not provided.');
        const { tokens } = await oauth2Client.getToken(code);
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const { data: { emailAddress } } = await gmail.users.getProfile({ userId: 'me' });
        if (!emailAddress) return res.redirect(`${frontendUrl}?error=email_not_retrieved`);

        const accountData = {
            host: 'imap.gmail.com', port: 993, user: emailAddress, authType: 'XOAUTH2',
            refreshToken: tokens.refresh_token, accessToken: tokens.access_token, tokenExpiry: new Date(tokens.expiry_date),
            password: null, authStatus: 'valid', lastError: null, updatedAt: new Date()
        };
        const update = { $set: {}, $setOnInsert: { createdAt: new Date() } };
        Object.keys(accountData).forEach(key => { if (accountData[key] !== undefined) update.$set[key] = accountData[key]; });
        
        await db.collection('accounts').updateOne({ user: emailAddress }, update, { upsert: true });
        res.redirect(`${frontendUrl}?auth_success=true`);
    } catch (error) {
        res.redirect(`${frontendUrl}?error=${error.message}`);
    }
});

app.post('/api/accounts', async (req, res) => {
    const { host, port, user, password } = req.body;
    
    // Block manual Gmail logins to prevent errors and guide users correctly
    if (host && host.toLowerCase().includes('gmail.com')) {
        return res.status(400).json({
            message: "Manual login for Gmail is not supported. Please use the 'Sign in with Google' button for all Gmail accounts."
        });
    }
    
    try {
        const testConfig = { imap: { host, port: parseInt(port, 10), tls: true, authTimeout: 15000, user, password, tlsOptions: { rejectUnauthorized: false } } };
        const testConnection = await imaps.connect(testConfig);
        await testConnection.end();

        const newAccount = { host, port: parseInt(port, 10), user, password: encrypt(password), authType: 'PLAIN', authStatus: 'valid', createdAt: new Date(), updatedAt: new Date() };
        const result = await db.collection('accounts').insertOne(newAccount);
        res.status(201).json({ message: 'Account added successfully!', accountId: result.insertedId });
    } catch (error) {
        console.error('Error adding account:', error.message);
        if (error.code === 11000) return res.status(409).json({ message: "An account with this email already exists." });
        
        const errMsg = error.message.toLowerCase();
        if (errMsg.includes('invalid credentials') || errMsg.includes('authentication failed')) {
            return res.status(400).json({ message: "Authentication failed. For services like Outlook or Yahoo, you may need an 'App Password'. Please generate one in your account's security settings." });
        }
        res.status(400).json({ message: `Connection failed: ${error.message}` });
    }
});

app.get('/api/accounts', async (req, res) => {
    try {
        const accounts = await db.collection('accounts').find({}, { projection: { password: 0, refreshToken: 0, accessToken: 0 } }).toArray();
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch accounts' });
    }
});

app.post('/api/process/:accountId', async (req, res) => {
    const { accountId } = req.params;
    const jobId = uuidv4();
    syncJobs[jobId] = { id: jobId, type: 'process', accountId, status: 'running', progress: { total: 0, processed: 0 }, error: null, createdAt: new Date() };
    processAccountEmails(jobId, accountId).catch(err => { syncJobs[jobId].status = 'failed'; syncJobs[jobId].error = err.message; });
    res.status(202).json({ message: 'Email processing started', jobId });
});

app.post('/api/sync/start', async (req, res) => {
    const { sourceAccountId, destAccountId } = req.body;
    if (sourceAccountId === destAccountId) return res.status(400).json({ message: 'Source and destination must be different' });
    const jobId = uuidv4();
    syncJobs[jobId] = { id: jobId, type: 'sync', sourceAccountId, destAccountId, status: 'running', progress: { total: 0, processed: 0 }, error: null, createdAt: new Date() };
    processEmailSync(jobId).catch(err => { syncJobs[jobId].status = 'failed'; syncJobs[jobId].error = err.message; });
    res.status(202).json({ message: 'Sync job started', jobId });
});

app.post('/api/sync/pause/:jobId', (req, res) => {
    const { jobId } = req.params;
    if (syncJobs[jobId]?.status === 'running') {
        syncJobs[jobId].status = 'paused';
        return res.json({ message: 'Job paused' });
    }
    res.status(404).json({ message: 'Job not found or not running' });
});

app.post('/api/sync/resume/:jobId', (req, res) => {
    const job = syncJobs[jobId];
    if (job?.status === 'paused') {
        job.status = 'running';
        const task = job.type === 'process' ? processAccountEmails(job.id, job.accountId) : processEmailSync(job.id);
        task.catch(err => { job.status = 'failed'; job.error = err.message; });
        return res.json({ message: 'Job resumed' });
    }
    res.status(404).json({ message: 'Job not found or not paused' });
});

app.get('/api/sync/status', (req, res) => {
    res.json(Object.values(syncJobs));
});

app.get('/api/emails', async (req, res) => {
    try {
        const { search, limit = 50, skip = 0 } = req.query;
        const query = search ? { $text: { $search: search } } : {};
        const emails = await db.collection('emails').find(query).sort({ receivedAt: -1 }).limit(parseInt(limit)).skip(parseInt(skip)).toArray();
        const total = await db.collection('emails').countDocuments(query);
        res.json({ emails, total });
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch emails' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const [totalEmails, espStats, domainStats] = await Promise.all([
            db.collection('emails').countDocuments(),
            db.collection('emails').aggregate([{ $group: { _id: '$analytics.esp', count: { $sum: 1 } } }]).toArray(),
            db.collection('emails').aggregate([{ $group: { _id: '$analytics.sendingDomain', count: { $sum: 1 } } }]).toArray()
        ]);
        res.json({ totalEmails, espDistribution: espStats, topDomains: domainStats });
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});


// --- CORE PROCESSING LOGIC ---
async function processAccountEmails(jobId, accountId) {
    const job = syncJobs[jobId];
    if (!job) return;
    try {
        await withConnection(accountId, async (connection) => {
            const boxes = await getSelectableMailboxes(connection);
            for (const boxName of Object.keys(boxes)) {
                if (job.status !== 'running') return;
                job.progress.currentFolder = boxName;
                await connection.openBox(boxName, true);
                const messages = await connection.search(['ALL'], { bodies: [''], struct: true });
                job.progress.total += messages.length;
                for (const message of messages) { 
                    if (job.status !== 'running') return; 
                    await processMessage(message, accountId); 
                    job.progress.processed++; 
                }
            }
        });
        if (job.status === 'running') job.status = 'completed';
    } catch (error) { 
        job.status = 'failed'; 
        job.error = error.message; 
    }
}

async function processMessage(message, accountId) {
    try {
        const allPart = message.parts.find(p => p.which === '');
        if (!allPart) return;
        const parsed = await simpleParser(allPart.body);
        if (!parsed.messageId) return;
        const fromAddr = parsed.from?.value?.[0]?.address || 'unknown';
        const domain = fromAddr.split('@')[1] || 'unknown';
        const [esp, security] = await Promise.all([detectESP(fromAddr, parsed.headers), checkMailServerSecurity(domain)]);
        const emailData = {
            accountId: new ObjectId(accountId), messageId: parsed.messageId, from: fromAddr, to: parsed.to?.text, subject: parsed.subject, body: parsed.text,
            receivedAt: message.attributes.date || new Date(), sentAt: parsed.date || new Date(), flags: message.flags || [],
            analytics: { sendingDomain: domain, esp, mailServerSecurity: security }
        };
        await db.collection('emails').updateOne({ messageId: emailData.messageId }, { $set: emailData }, { upsert: true });
    } catch (error) { 
        console.error('Error processing message:', error); 
    }
}

async function processEmailSync(jobId) {
    const job = syncJobs[jobId];
    if (!job) return;
    try {
        await withConnection(job.sourceAccountId, async (sourceConn) => {
            await withConnection(job.destAccountId, async (destConn) => {
                const boxes = await getSelectableMailboxes(sourceConn);
                for (const boxName of Object.keys(boxes)) {
                    if (job.status !== 'running') return;
                    job.progress.currentFolder = boxName;
                    await sourceConn.openBox(boxName, true);
                    try { await destConn.addBox(boxName); } catch (e) { /* Box likely exists */ }
                    const messages = await sourceConn.search(['ALL'], { bodies: [''], struct: true });
                    job.progress.total += messages.length;
                    for (const message of messages) {
                        if (job.status !== 'running') return;
                        const allPart = message.parts.find(part => part.which === '');
                        if (allPart) {
                            await destConn.append(allPart.body, { mailbox: boxName, flags: message.flags.filter(f => f !== '\\Recent'), date: message.attributes.date });
                            await processMessage(message, job.sourceAccountId);
                            job.progress.processed++;
                        }
                    }
                }
            });
        });
        if (job.status === 'running') job.status = 'completed';
    } catch (error) {
        job.status = 'failed';
        job.error = error.message;
    }
}

async function getSelectableMailboxes(connection) {
    const mailboxes = await connection.getBoxes();
    const selectable = {};
    function findSelectable(boxes, prefix = '') {
        for (const name in boxes) {
            const path = prefix ? `${prefix}${boxes[name].delimiter}${name}` : name;
            if (!boxes[name].attribs.includes('\\Noselect')) {
                selectable[path] = boxes[name];
            }
            if (boxes[name].children && Object.keys(boxes[name].children).length > 0) {
                findSelectable(boxes[name].children, path);
            }
        }
    }
    findSelectable(mailboxes);
    return selectable;
}


// --- CLEANUP AND START SERVER ---
async function shutdown(signal) {
    console.log(`Received ${signal}. Shutting down...`);
    for (const [id, pool] of connectionPools.entries()) { 
        try { 
            await pool.drain(); 
            await pool.clear(); 
        } catch (e) { 
            console.error(`Error closing pool for ${id}`); 
        } 
    }
    if (mongoClient) await mongoClient.close();
    process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

MongoClient.connect(mongoUri)
    .then(async (client) => {
        mongoClient = client;
        db = client.db();
        await db.collection('accounts').createIndex({ user: 1 }, { unique: true });
        await db.collection('emails').createIndex({ messageId: 1 }, { unique: true });
        await db.collection('emails').createIndex({ subject: 'text', body: 'text' });
        console.log("✓ Connected to MongoDB and created indexes");
        app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
    })
    .catch(err => { 
        console.error("✗ Could not connect to MongoDB.", err); 
        process.exit(1); 
    });