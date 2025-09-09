const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const imaps = require('imap-simple');
const { simpleParser } = require('mailparser');
const dotenv = require('dotenv');
const { google } = require('googleapis');
const genericPool = require('generic-pool');
const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

dotenv.config();

// --- CONFIGURATION ---
const app = express();
const port = process.env.PORT || 3001;
const mongoUri = process.env.MONGO_URI || 'mongodb+srv://amitmeel:meelamit3838@cluster0.klncho3.mongodb.net/emailTask?retryWrites=true&w=majority&appName=Cluster0';

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback'
);

// --- MIDDLEWARE ---
app.use(express.json());
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// --- DATABASE & GLOBALS ---
let db;
let mongoClient;
const syncJobs = {};
const connectionPools = new Map();

// --- HELPERS ---
const encrypt = (text) => Buffer.from(text).toString('base64');
const decrypt = (text) => Buffer.from(text, 'base64').toString('ascii');

/**
 * Construct the XOAUTH2 SASL token
 */
const constructXOAuth2Token = (user, accessToken) => {
    const authString = `user=${user}\x01auth=Bearer ${accessToken}\x01\x01`;
    return Buffer.from(authString).toString('base64');
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
                await db.collection('accounts').updateOne(
                    { _id: currentAccount._id }, 
                    { $set: { authStatus: 'valid', lastError: null } }
                );
                return connection;
            } catch (error) {
                console.error(`✗ Failed to create connection for ${currentAccount.user}:`, error.message);
                await db.collection('accounts').updateOne(
                    { _id: currentAccount._id }, 
                    { $set: { authStatus: 'error', lastError: error.message } }
                );
                throw error;
            }
        },
        destroy: (connection) => {
            if (connection && typeof connection.end === 'function') {
                connection.end();
            }
        },
        validate: (connection) => {
            return connection && connection.state !== 'disconnected';
        }
    };

    const pool = genericPool.createPool(factory, {
        min: 0,
        max: 3,
        acquireTimeoutMillis: 30000,
        idleTimeoutMillis: 30000,
        evictionRunIntervalMillis: 10000,
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
    const espPatterns = {
        'Gmail': ['gmail.com', 'googlemail.com'],
        'Outlook': ['outlook.com', 'hotmail.com', 'live.com'],
        'Yahoo': ['yahoo.com', 'ymail.com'],
        'Amazon SES': ['amazonses.com'],
        'SendGrid': ['sendgrid.net'],
        'Mailchimp': ['mailchimp.com'],
        'Constant Contact': ['constantcontact.com']
    };

    for (const [esp, domains] of Object.entries(espPatterns)) {
        if (domains.some(d => domain.includes(d))) return esp;
    }

    const receivedHeaders = Array.isArray(headers.get('received')) ? 
        headers.get('received') : 
        [headers.get('received')];
    
    for (const received of receivedHeaders) {
        if (!received) continue;
        if (received.includes('gmail.com')) return 'Gmail';
        if (received.includes('outlook.com')) return 'Outlook';
        if (received.includes('yahoo.com')) return 'Yahoo';
        if (received.includes('amazonses.com')) return 'Amazon SES';
        if (received.includes('sendgrid.net')) return 'SendGrid';
    }

    return 'Unknown';
}

async function checkMailServerSecurity(domain) {
    try {
        const mxRecords = await dns.resolveMx(domain);
        if (!mxRecords || mxRecords.length === 0) {
            return { hasValidMX: false, supportsTLS: false, hasValidCert: false, isOpenRelay: false };
        }

        const primaryMX = mxRecords.sort((a, b) => a.priority - b.priority)[0];
        const mxHost = primaryMX.exchange;

        const tlsResult = await new Promise((resolve) => {
            const socket = tls.connect({ port: 25, host: mxHost, rejectUnauthorized: false, timeout: 5000 });
            
            socket.on('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve({ supportsTLS: true, hasValidCert: socket.authorized, certInfo: cert });
            });
            
            socket.on('error', () => resolve({ supportsTLS: false, hasValidCert: false }));
            socket.on('timeout', () => {
                socket.destroy();
                resolve({ supportsTLS: false, hasValidCert: false });
            });
        });

        return {
            hasValidMX: true,
            mxHost: mxHost,
            supportsTLS: tlsResult.supportsTLS,
            hasValidCert: tlsResult.hasValidCert,
            isOpenRelay: false
        };
    } catch (error) {
        return { hasValidMX: false, supportsTLS: false, hasValidCert: false, isOpenRelay: false };
    }
}

// --- API ENDPOINTS ---

app.get('/api/auth/google', (req, res) => {
    const { accountId } = req.query;
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['https://mail.google.com/'],
        state: accountId || null,
    });
    res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code, state } = req.query;
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

    try {
        if (req.query.error || !code) {
            throw new Error(req.query.error || 'Authorization code not provided.');
        }

        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const profile = await gmail.users.getProfile({ userId: 'me' });
        const userEmail = profile.data.emailAddress;

        if (!userEmail) {
            return res.redirect(`${frontendUrl}?error=email_not_retrieved`);
        }

        const accountData = {
            host: 'imap.gmail.com',
            port: 993,
            user: userEmail,
            authType: 'XOAUTH2',
            refreshToken: tokens.refresh_token,
            accessToken: tokens.access_token,
            tokenExpiry: new Date(tokens.expiry_date),
            password: null,
            authStatus: 'valid',
            lastError: null,
            updatedAt: new Date()
        };
        
        const updateOperation = { $set: accountData };
        const query = state ? { _id: new ObjectId(state) } : { user: userEmail };

        await db.collection('accounts').updateOne(
            query,
            { ...updateOperation, $setOnInsert: { createdAt: new Date() } },
            { upsert: true }
        );

        res.redirect(`${frontendUrl}?auth_success=true&email=${encodeURIComponent(userEmail)}`);

    } catch (error) {
        console.error('Error during Google OAuth callback:', error);
        res.redirect(`${frontendUrl}?error=${encodeURIComponent(error.message)}`);
    }
});

app.post('/api/accounts', async (req, res) => {
    const { host, port, user, password } = req.body;
    
    try {
        const testConfig = {
            imap: { 
                host, 
                port: parseInt(port, 10), 
                tls: true, 
                authTimeout: 15000,
                connTimeout: 15000, 
                user, 
                password, 
                tlsOptions: { 
                    rejectUnauthorized: false,
                    servername: host
                } 
            }
        };
        
        console.log(`Testing IMAP connection for ${user}@${host}:${port}`);
        const testConnection = await imaps.connect(testConfig);
        await testConnection.end();
        console.log(`✓ IMAP connection successful for ${user}`);

        const newAccount = {
            host, 
            port: parseInt(port, 10), 
            user, 
            password: encrypt(password), 
            authType: 'PLAIN', 
            authStatus: 'valid', 
            lastError: null,
            createdAt: new Date(), 
            updatedAt: new Date()
        };

        const result = await db.collection('accounts').insertOne(newAccount);
        res.status(201).json({ 
            message: 'Account added successfully!', 
            accountId: result.insertedId 
        });
    } catch (error) {
        console.error('Error adding account:', error.message);
        
        if (error.code === 11000) {
            return res.status(409).json({ message: "An account with this email already exists." });
        }
        
        const errorMessage = error.message.toLowerCase();
        
        if (errorMessage.includes('invalid credentials') || 
            errorMessage.includes('authentication failed') ||
            errorMessage.includes('login failed') ||
            errorMessage.includes('[authenticationfailed]')) {
            return res.status(400).json({ 
                message: "Authentication failed. Please check your credentials. If using Gmail, Yahoo, or Outlook, you may need to use an 'App Password' instead of your regular password. Generate one in your account's security settings and try again." 
            });
        }
        
        if (errorMessage.includes('connection') || errorMessage.includes('timeout')) {
            return res.status(400).json({ 
                message: "Connection failed. Please check the server settings (host and port) and try again." 
            });
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

app.delete('/api/accounts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.collection('accounts').deleteOne({ _id: new ObjectId(id) });
        
        // Clean up any connection pool for this account
        if (connectionPools.has(id)) {
            const pool = connectionPools.get(id);
            await pool.drain();
            await pool.clear();
            connectionPools.delete(id);
        }
        
        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete account' });
    }
});

app.post('/api/process/:accountId', async (req, res) => {
    const { accountId } = req.params;
    try {
        const jobId = uuidv4();
        syncJobs[jobId] = { 
            id: jobId, 
            type: 'process', 
            accountId, 
            status: 'running', 
            progress: { total: 0, processed: 0, currentFolder: '' }, 
            error: null, 
            createdAt: new Date() 
        };
        
        processAccountEmails(jobId, accountId).catch(err => {
            console.error(`Processing job ${jobId} failed:`, err);
            syncJobs[jobId].status = 'failed';
            syncJobs[jobId].error = err.message;
        });
        
        res.status(202).json({ message: 'Email processing started', jobId });
    } catch (error) {
        console.error('Error starting processing:', error);
        res.status(500).json({ message: 'Failed to start processing' });
    }
});

app.post('/api/sync/start', async (req, res) => {
    const { sourceAccountId, destAccountId } = req.body;
    if (sourceAccountId === destAccountId) {
        return res.status(400).json({ message: 'Source and destination must be different' });
    }
    try {
        const jobId = uuidv4();
        syncJobs[jobId] = { 
            id: jobId, 
            type: 'sync', 
            sourceAccountId, 
            destAccountId, 
            status: 'running', 
            progress: { total: 0, processed: 0, currentFolder: '' }, 
            error: null, 
            createdAt: new Date() 
        };
        
        processEmailSync(jobId).catch(err => {
            console.error(`Sync job ${jobId} failed:`, err);
            syncJobs[jobId].status = 'failed';
            syncJobs[jobId].error = err.message;
        });
        
        res.status(202).json({ message: 'Sync job started', jobId });
    } catch (error) {
        console.error('Error starting sync:', error);
        res.status(500).json({ message: 'Failed to start sync' });
    }
});

app.post('/api/sync/pause/:jobId', (req, res) => {
    const { jobId } = req.params;
    if (syncJobs[jobId] && syncJobs[jobId].status === 'running') {
        syncJobs[jobId].status = 'paused';
        res.json({ message: 'Job paused' });
    } else {
        res.status(404).json({ message: 'Job not found or not running' });
    }
});

app.post('/api/sync/resume/:jobId', (req, res) => {
    const { jobId } = req.params;
    const job = syncJobs[jobId];
    if (job && job.status === 'paused') {
        job.status = 'running';
        const task = job.type === 'process' ? 
            processAccountEmails(jobId, job.accountId) : 
            processEmailSync(jobId);
        
        task.catch(err => {
            console.error(`Job ${jobId} failed on resume:`, err);
            job.status = 'failed';
            job.error = err.message;
        });
        
        res.json({ message: 'Job resumed' });
    } else {
        res.status(404).json({ message: 'Job not found or not paused' });
    }
});

app.get('/api/status', (req, res) => {
    res.json(Object.values(syncJobs));
});

app.get('/api/sync/status', (req, res) => {
    res.json(Object.values(syncJobs));
});

app.get('/api/emails', async (req, res) => {
    try {
        const { search, limit = 50, skip = 0, accountId } = req.query;
        let query = {};
        
        if (accountId) {
            query.accountId = new ObjectId(accountId);
        }
        
        if (search) {
            query.$or = [
                { from: { $regex: search, $options: 'i' } },
                { subject: { $regex: search, $options: 'i' } },
                { body: { $regex: search, $options: 'i' } }
            ];
        }
        
        const emails = await db.collection('emails')
            .find(query)
            .sort({ receivedAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .toArray();
            
        const total = await db.collection('emails').countDocuments(query);
        res.json({ emails, total });
    } catch (error) {
        console.error('Error fetching emails:', error);
        res.status(500).json({ message: 'Failed to fetch emails' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const [totalEmails, espStats, domainStats] = await Promise.all([
            db.collection('emails').countDocuments(),
            db.collection('emails').aggregate([
                { $group: { _id: '$analytics.esp', count: { $sum: 1 } } }, 
                { $sort: { count: -1 } }
            ]).toArray(),
            db.collection('emails').aggregate([
                { $group: { _id: '$analytics.sendingDomain', count: { $sum: 1 } } }, 
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]).toArray()
        ]);
        
        res.json({ totalEmails, espDistribution: espStats, topDomains: domainStats });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});

// --- CORE PROCESSING LOGIC ---
async function processAccountEmails(jobId, accountId) {
    const job = syncJobs[jobId];
    if (!job) return;
    
    console.log(`Starting email processing for account ${accountId}`);
    
    try {
        await withConnection(accountId, async (connection) => {
            const boxes = await getSelectableMailboxes(connection);
            console.log(`Found ${Object.keys(boxes).length} mailboxes to process`);
            
            for (const boxName of Object.keys(boxes)) {
                if (job.status !== 'running') {
                    console.log(`Job ${jobId} is no longer running, stopping processing`);
                    return;
                }
                
                console.log(`Processing mailbox: ${boxName}`);
                job.progress.currentFolder = boxName;
                
                await connection.openBox(boxName, true);
                const messages = await connection.search(['ALL'], { bodies: [''], struct: true });
                
                console.log(`Found ${messages.length} messages in ${boxName}`);
                job.progress.total += messages.length;
                
                for (const message of messages) {
                    if (job.status !== 'running') return;
                    await processMessage(message, accountId);
                    job.progress.processed++;
                }
            }
        });
        
        if (job.status === 'running') {
            job.status = 'completed';
            console.log(`✓ Email processing completed for account ${accountId}`);
        }
    } catch (error) {
        console.error(`✗ Email processing failed for account ${accountId}:`, error.message);
        job.status = 'failed';
        job.error = error.message;
    }
}

async function processMessage(message, accountId) {
    try {
        const allPart = message.parts.find(part => part.which === '');
        if (!allPart) return;
        
        const parsedMail = await simpleParser(allPart.body);
        if (!parsedMail.messageId) return;
        
        const fromAddress = parsedMail.from?.value?.[0]?.address || 'unknown';
        const sendingDomain = fromAddress.split('@')[1] || 'unknown';
        
        const [esp, mailServerSecurity] = await Promise.all([
            detectESP(fromAddress, parsedMail.headers),
            checkMailServerSecurity(sendingDomain)
        ]);

        const sentDate = parsedMail.date || new Date();
        const receivedDate = message.attributes.date || new Date();

        const emailData = {
            accountId: new ObjectId(accountId),
            messageId: parsedMail.messageId,
            from: fromAddress,
            to: parsedMail.to?.text,
            subject: parsedMail.subject,
            body: parsedMail.text,
            receivedAt: receivedDate,
            sentAt: sentDate,
            flags: message.flags || [],
            analytics: {
                sendingDomain,
                esp,
                sentReceivedDelta: Math.round((receivedDate.getTime() - sentDate.getTime()) / 1000),
                mailServerSecurity
            }
        };
        
        await db.collection('emails').updateOne(
            { messageId: emailData.messageId, accountId: emailData.accountId }, 
            { $set: emailData }, 
            { upsert: true }
        );
    } catch (error) {
        console.error('Error processing individual message:', error);
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
                    try { 
                        await destConn.addBox(boxName); 
                    } catch (e) { 
                        // Box likely exists, ignore error
                    }
                    
                    const messages = await sourceConn.search(['ALL'], { bodies: [''], struct: true });
                    job.progress.total += messages.length;
                    
                    for (const message of messages) {
                        if (job.status !== 'running') return;
                        const allPart = message.parts.find(part => part.which === '');
                        await destConn.append(
                            allPart.body, 
                            { 
                                mailbox: boxName, 
                                flags: message.flags.filter(f => f !== '\\Recent'), 
                                date: message.attributes.date 
                            }
                        );
                        await processMessage(message, job.sourceAccountId);
                        job.progress.processed++;
                    }
                }
            });
        });
        
        if (job.status === 'running') {
            job.status = 'completed';
        }
    } catch (error) {
        console.error(`Sync job ${jobId} failed:`, error);
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
            if (boxes[name].children) {
                findSelectable(boxes[name].children, path);
            }
        }
    }
    
    findSelectable(mailboxes);
    return selectable;
}

// --- CLEANUP AND START SERVER ---
async function shutdown(signal) {
    console.log(`Received ${signal}. Shutting down gracefully...`);
    
    for (const [accountId, pool] of connectionPools.entries()) {
        try {
            await pool.drain();
            await pool.clear();
            console.log(`Pool for account ${accountId} cleared.`);
        } catch (error) {
            console.error(`Error closing pool for account ${accountId}:`, error);
        }
    }

    if (mongoClient) {
        await mongoClient.close();
        console.log("MongoDB connection closed.");
    }

    process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Initialize the server
MongoClient.connect(mongoUri)
    .then(async (client) => {
        mongoClient = client;
        db = client.db();
        
        // Create indexes
        await Promise.all([
            db.collection('emails').createIndex({ messageId: 1, accountId: 1 }, { unique: true }),
            db.collection('emails').createIndex({ from: 1 }),
            db.collection('emails').createIndex({ subject: 'text', body: 'text' }),
            db.collection('emails').createIndex({ receivedAt: -1 }),
            db.collection('emails').createIndex({ accountId: 1 }),
            db.collection('accounts').createIndex({ user: 1 }, { unique: true })
        ]);
        
        console.log("✓ Connected to MongoDB and created indexes");
        
        app.listen(port, () => {
            console.log(`🚀 Email Sync & Analytics Hub running on http://localhost:${port}`);
        });
    })
    .catch(err => {
        console.error("✗ Could not connect to MongoDB.", err);
        process.exit(1);
    });