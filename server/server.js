
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
let mongoClient;
const syncJobs = {};
const connectionPools = new Map();

// --- HELPERS ---
const encrypt = (text) => Buffer.from(text).toString('base64');
const decrypt = (text) => Buffer.from(text, 'base64').toString('ascii');

/**
 * Constructs proper XOAUTH2 SASL token for Gmail authentication
 */
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
            { 
                $set: { 
                    accessToken: account.accessToken, 
                    tokenExpiry: account.tokenExpiry,
                    authStatus: 'valid',
                    lastError: null
                } 
            }
        );
        
        console.log(`✓ Token refreshed for ${account.user}`);
        return account;
    } catch (error) {
        console.error(`✗ Failed to refresh token for ${account.user}:`, error.response?.data || error.message);
        
        await db.collection('accounts').updateOne(
            { _id: account._id },
            { 
                $set: { 
                    authStatus: 'invalid', 
                    lastError: 'Token refresh failed. Please re-authenticate.' 
                } 
            }
        );
        throw new Error('Token refresh failed. Please re-authenticate.');
    }
}

function createPoolForAccount(account) {
    const poolKey = account._id.toString();
    
    if (connectionPools.has(poolKey)) {
        return connectionPools.get(poolKey);
    }

    const factory = {
        create: async () => {
            console.log(`Creating IMAP connection for ${account.user}`);
            
            let currentAccount = { ...account };

            // Handle OAuth2 token refresh
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
                    authTimeout: 30000,
                    connTimeout: 30000,
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
                console.log(`✓ IMAP connection established for ${currentAccount.user}`);
                
                // Update account status on successful connection
                await db.collection('accounts').updateOne(
                    { _id: currentAccount._id }, 
                    { 
                        $set: { 
                            authStatus: 'valid', 
                            lastError: null,
                            lastConnected: new Date()
                        } 
                    }
                );
                
                return connection;
            } catch (error) {
                console.error(`✗ Failed to create IMAP connection for ${currentAccount.user}:`, error.message);
                
                // Update account status on failed connection
                await db.collection('accounts').updateOne(
                    { _id: currentAccount._id }, 
                    { 
                        $set: { 
                            authStatus: 'error', 
                            lastError: error.message,
                            lastErrorAt: new Date()
                        } 
                    }
                );
                
                throw error;
            }
        },
        destroy: (connection) => {
            try {
                if (connection && connection.state !== 'disconnected') {
                    connection.end();
                    console.log(`Connection destroyed for ${connection._config?.user || 'unknown'}`);
                }
            } catch (error) {
                console.error('Error destroying connection:', error.message);
            }
        }
    };

    const pool = genericPool.createPool(factory, {
        min: 0,
        max: 3,
        acquireTimeoutMillis: 45000,
        createTimeoutMillis: 45000,
        destroyTimeoutMillis: 5000,
        idleTimeoutMillis: 300000, // 5 minutes
    });
    
    pool.on('factoryCreateError', (err) => {
        console.error(`Pool factory error for ${account.user}:`, err.message);
    });

    connectionPools.set(poolKey, pool);
    return pool;
}

async function withConnection(accountId, callback) {
    const account = await db.collection('accounts').findOne({ _id: new ObjectId(accountId) });
    if (!account) {
        throw new Error("Account not found");
    }

    if (account.authStatus === 'invalid') {
        throw new Error(`Authentication for ${account.user} is invalid. Please re-authenticate.`);
    }

    const pool = createPoolForAccount(account);
    let connection;
    
    try {
        connection = await pool.acquire();
        return await callback(connection);
    } catch (error) {
        console.error(`Error in withConnection for ${account.user}:`, error.message);
        throw error;
    } finally {
        if (connection) {
            try {
                await pool.release(connection);
            } catch (releaseError) {
                console.error('Error releasing connection:', releaseError.message);
            }
        }
    }
}

// --- EMAIL ANALYTICS FUNCTIONS ---
async function detectESP(fromAddress, headers) {
    const domain = fromAddress.split('@')[1] || 'unknown.com';
    
    const espPatterns = {
        'Gmail': ['gmail.com', 'googlemail.com'],
        'Outlook': ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'],
        'Yahoo': ['yahoo.com', 'ymail.com', 'rocketmail.com'],
        'Amazon SES': ['amazonses.com'],
        'SendGrid': ['sendgrid.net', 'sendgrid.com'],
        'Mailchimp': ['mailchimp.com', 'mcsv.net'],
        'Constant Contact': ['constantcontact.com'],
        'Campaign Monitor': ['createsend.com'],
        'Mailgun': ['mailgun.org', 'mg.domain.com']
    };

    // Check domain patterns first
    for (const [esp, domains] of Object.entries(espPatterns)) {
        if (domains.some(d => domain.includes(d) || d.includes(domain))) {
            return esp;
        }
    }

    // Check headers for ESP signatures
    if (headers) {
        const receivedHeaders = headers.get('received');
        const xOriginatingIP = headers.get('x-originating-ip');
        const xMailer = headers.get('x-mailer');
        
        const headerText = [receivedHeaders, xOriginatingIP, xMailer].join(' ').toLowerCase();
        
        for (const [esp, domains] of Object.entries(espPatterns)) {
            if (domains.some(d => headerText.includes(d))) {
                return esp;
            }
        }
    }

    return 'Unknown';
}

async function checkMailServerSecurity(domain) {
    try {
        const mxRecords = await dns.resolveMx(domain);
        if (!mxRecords || mxRecords.length === 0) {
            return { 
                hasValidMX: false, 
                supportsTLS: false, 
                hasValidCert: false, 
                mxHost: null 
            };
        }

        const primaryMX = mxRecords.sort((a, b) => a.priority - b.priority)[0];
        const mxHost = primaryMX.exchange;

        const tlsResult = await new Promise((resolve) => {
            const socket = tls.connect({ 
                port: 25, 
                host: mxHost, 
                rejectUnauthorized: false, 
                timeout: 10000 
            });
            
            socket.on('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve({ 
                    supportsTLS: true, 
                    hasValidCert: socket.authorized,
                    certInfo: {
                        subject: cert.subject,
                        issuer: cert.issuer,
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to
                    }
                });
            });
            
            socket.on('error', () => {
                resolve({ supportsTLS: false, hasValidCert: false });
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve({ supportsTLS: false, hasValidCert: false });
            });
        });

        return {
            hasValidMX: true,
            mxHost: mxHost,
            ...tlsResult
        };
    } catch (error) {
        console.error(`Error checking mail server security for ${domain}:`, error.message);
        return { 
            hasValidMX: false, 
            supportsTLS: false, 
            hasValidCert: false, 
            mxHost: null 
        };
    }
}

// --- API ENDPOINTS ---

// OAuth2 Authentication
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
    const frontendUrl = process.env.FRONTEND_URL || "https://sync-email-dashboard.vercel.app/";

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
            lastConnected: new Date(),
            updatedAt: new Date()
        };
        
        const query = state ? { _id: new ObjectId(state) } : { user: userEmail };

        await db.collection('accounts').updateOne(
            query,
            { 
                $set: accountData, 
                $setOnInsert: { createdAt: new Date() } 
            },
            { upsert: true }
        );

        console.log(`✓ Google OAuth completed for ${userEmail}`);
        res.redirect(`${frontendUrl}?auth_success=true`);

    } catch (error) {
        console.error('Error during Google OAuth callback:', error);
        res.redirect(`${frontendUrl}?error=${encodeURIComponent(error.message)}`);
    }
});

// Manual Account Addition
app.post('/api/accounts', async (req, res) => {
    const { host, port, user, password } = req.body;
    
    if (!host || !port || !user || !password) {
        return res.status(400).json({ 
            message: 'All fields (host, port, user, password) are required.' 
        });
    }
    
    try {
        // Test connection before saving
        const testConfig = {
            imap: { 
                host, 
                port: parseInt(port, 10), 
                tls: true, 
                authTimeout: 20000,
                connTimeout: 20000, 
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
        console.log(`✓ IMAP connection test successful for ${user}`);

        const newAccount = {
            host, 
            port: parseInt(port, 10), 
            user, 
            password: encrypt(password), 
            authType: 'PLAIN', 
            authStatus: 'valid', 
            lastError: null,
            lastConnected: new Date(),
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
            return res.status(409).json({ 
                message: "An account with this email already exists." 
            });
        }
        
        // Enhanced error messages for common authentication issues
        const errorMessage = error.message.toLowerCase();
        
        if (errorMessage.includes('invalid credentials') || 
            errorMessage.includes('authentication failed') ||
            errorMessage.includes('login failed') ||
            errorMessage.includes('[authenticationfailed]') ||
            errorMessage.includes('auth failed')) {
            return res.status(400).json({ 
                message: "❌ Authentication failed. If using Gmail, Yahoo, or Outlook, you MUST use an 'App Password' instead of your regular password.\n\n📋 Steps to create an App Password:\n• Gmail: Google Account → Security → 2-Step Verification → App passwords\n• Yahoo: Account Security → Generate app password\n• Outlook: Microsoft Account → Security → App passwords\n\nThen use the generated app password here instead of your regular password." 
            });
        }
        
        if (errorMessage.includes('connection') || 
            errorMessage.includes('timeout') ||
            errorMessage.includes('enotfound') ||
            errorMessage.includes('econnrefused')) {
            return res.status(400).json({ 
                message: "❌ Connection failed. Please verify:\n• Host name is correct (e.g., imap.gmail.com)\n• Port number is correct (usually 993 for SSL/TLS)\n• Internet connection is stable\n• Firewall isn't blocking the connection" 
            });
        }
        
        res.status(400).json({ 
            message: `Connection failed: ${error.message}` 
        });
    }
});

// Get Accounts
app.get('/api/accounts', async (req, res) => {
    try {
        const accounts = await db.collection('accounts').find(
            {}, 
            { 
                projection: { 
                    password: 0, 
                    refreshToken: 0, 
                    accessToken: 0 
                } 
            }
        ).toArray();
        
        res.json(accounts);
    } catch (error) {
        console.error('Error fetching accounts:', error);
        res.status(500).json({ message: 'Failed to fetch accounts' });
    }
});

// Delete Account
app.delete('/api/accounts/:accountId', async (req, res) => {
    try {
        const { accountId } = req.params;
        
        // Clean up connection pool
        const poolKey = accountId;
        if (connectionPools.has(poolKey)) {
            const pool = connectionPools.get(poolKey);
            await pool.drain();
            await pool.clear();
            connectionPools.delete(poolKey);
        }
        
        // Delete from database
        const result = await db.collection('accounts').deleteOne({ 
            _id: new ObjectId(accountId) 
        });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'Account not found' });
        }
        
        // Also delete associated emails
        await db.collection('emails').deleteMany({ 
            accountId: new ObjectId(accountId) 
        });
        
        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ message: 'Failed to delete account' });
    }
});

// Process Account Emails
app.post('/api/process/:accountId', async (req, res) => {
    const { accountId } = req.params;
    
    try {
        const account = await db.collection('accounts').findOne({ 
            _id: new ObjectId(accountId) 
        });
        
        if (!account) {
            return res.status(404).json({ message: 'Account not found' });
        }
        
        const jobId = uuidv4();
        syncJobs[jobId] = { 
            id: jobId, 
            type: 'process', 
            accountId, 
            status: 'running', 
            progress: { 
                total: 0, 
                processed: 0, 
                currentFolder: '',
                errors: 0
            }, 
            error: null, 
            createdAt: new Date() 
        };
        
        // Start processing in background
        processAccountEmails(jobId, accountId).catch(err => {
            console.error(`Processing job ${jobId} failed:`, err);
            syncJobs[jobId].status = 'failed';
            syncJobs[jobId].error = err.message;
        });
        
        res.status(202).json({ 
            message: 'Email processing started', 
            jobId,
            account: account.user
        });
        
    } catch (error) {
        console.error('Error starting email processing:', error);
        res.status(500).json({ message: 'Failed to start processing' });
    }
});

// Sync Jobs
app.post('/api/sync/start', async (req, res) => {
    const { sourceAccountId, destAccountId } = req.body;
    
    if (!sourceAccountId || !destAccountId) {
        return res.status(400).json({ 
            message: 'Both source and destination account IDs are required' 
        });
    }
    
    if (sourceAccountId === destAccountId) {
        return res.status(400).json({ 
            message: 'Source and destination accounts must be different' 
        });
    }
    
    try {
        // Verify both accounts exist
        const [sourceAccount, destAccount] = await Promise.all([
            db.collection('accounts').findOne({ _id: new ObjectId(sourceAccountId) }),
            db.collection('accounts').findOne({ _id: new ObjectId(destAccountId) })
        ]);
        
        if (!sourceAccount) {
            return res.status(404).json({ message: 'Source account not found' });
        }
        
        if (!destAccount) {
            return res.status(404).json({ message: 'Destination account not found' });
        }
        
        const jobId = uuidv4();
        syncJobs[jobId] = { 
            id: jobId, 
            type: 'sync', 
            sourceAccountId, 
            destAccountId, 
            status: 'running', 
            progress: { 
                total: 0, 
                processed: 0, 
                currentFolder: '',
                errors: 0
            }, 
            error: null, 
            createdAt: new Date() 
        };
        
        // Start sync in background
        processEmailSync(jobId).catch(err => {
            console.error(`Sync job ${jobId} failed:`, err);
            syncJobs[jobId].status = 'failed';
            syncJobs[jobId].error = err.message;
        });
        
        res.status(202).json({ 
            message: 'Sync job started', 
            jobId,
            source: sourceAccount.user,
            destination: destAccount.user
        });
        
    } catch (error) {
        console.error('Error starting sync job:', error);
        res.status(500).json({ message: 'Failed to start sync' });
    }
});

app.post('/api/sync/pause/:jobId', (req, res) => {
    const { jobId } = req.params;
    const job = syncJobs[jobId];
    
    if (!job) {
        return res.status(404).json({ message: 'Job not found' });
    }
    
    if (job.status !== 'running') {
        return res.status(400).json({ 
            message: `Job is not running (current status: ${job.status})` 
        });
    }
    
    job.status = 'paused';
    res.json({ message: 'Job paused successfully' });
});

app.post('/api/sync/resume/:jobId', (req, res) => {
    const { jobId } = req.params;
    const job = syncJobs[jobId];
    
    if (!job) {
        return res.status(404).json({ message: 'Job not found' });
    }
    
    if (job.status !== 'paused') {
        return res.status(400).json({ 
            message: `Job is not paused (current status: ${job.status})` 
        });
    }
    
    job.status = 'running';
    
    const task = job.type === 'process' 
        ? processAccountEmails(jobId, job.accountId) 
        : processEmailSync(jobId);
        
    task.catch(err => {
        console.error(`Resumed job ${jobId} failed:`, err);
        job.status = 'failed';
        job.error = err.message;
    });
    
    res.json({ message: 'Job resumed successfully' });
});

// Job Status Endpoints
app.get('/api/status', (req, res) => {
    const jobs = Object.values(syncJobs).map(job => ({
        ...job,
        duration: job.createdAt ? Date.now() - job.createdAt.getTime() : 0
    }));
    
    res.json(jobs);
});

app.get('/api/sync/status', (req, res) => {
    // Keep for backward compatibility
    const jobs = Object.values(syncJobs).map(job => ({
        ...job,
        duration: job.createdAt ? Date.now() - job.createdAt.getTime() : 0
    }));
    
    res.json(jobs);
});

// Get specific job status
app.get('/api/status/:jobId', (req, res) => {
    const { jobId } = req.params;
    const job = syncJobs[jobId];
    
    if (!job) {
        return res.status(404).json({ message: 'Job not found' });
    }
    
    res.json({
        ...job,
        duration: job.createdAt ? Date.now() - job.createdAt.getTime() : 0
    });
});

// Cancel job
app.delete('/api/jobs/:jobId', (req, res) => {
    const { jobId } = req.params;
    const job = syncJobs[jobId];
    
    if (!job) {
        return res.status(404).json({ message: 'Job not found' });
    }
    
    job.status = 'cancelled';
    res.json({ message: 'Job cancelled successfully' });
});

// Email Data
app.get('/api/emails', async (req, res) => {
    try {
        const { 
            search, 
            limit = 50, 
            skip = 0, 
            accountId,
            sortBy = 'receivedAt',
            sortOrder = 'desc'
        } = req.query;
        
        let query = {};
        
        if (accountId) {
            query.accountId = new ObjectId(accountId);
        }
        
        if (search) {
            query.$or = [
                { subject: { $regex: search, $options: 'i' } },
                { from: { $regex: search, $options: 'i' } },
                { body: { $regex: search, $options: 'i' } }
            ];
        }
        
        const sortOptions = {};
        sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
        
        const [emails, total] = await Promise.all([
            db.collection('emails')
                .find(query)
                .sort(sortOptions)
                .limit(parseInt(limit))
                .skip(parseInt(skip))
                .toArray(),
            db.collection('emails').countDocuments(query)
        ]);
        
        res.json({ 
            emails, 
            total,
            page: Math.floor(parseInt(skip) / parseInt(limit)) + 1,
            totalPages: Math.ceil(total / parseInt(limit))
        });
        
    } catch (error) {
        console.error('Error fetching emails:', error);
        res.status(500).json({ message: 'Failed to fetch emails' });
    }
});

// Statistics
app.get('/api/stats', async (req, res) => {
    try {
        const { accountId } = req.query;
        console.log("AccountId received:", accountId); // FIXED: Better logging
        
        let matchStage = {};
        
        if (accountId && ObjectId.isValid(accountId)) { // FIXED: Validate ObjectId
            matchStage.accountId = new ObjectId(accountId);
        }
        
        const [
            totalEmails,
            espStats,
            domainStats,
            dailyStats,
            accountStats
        ] = await Promise.all([
            db.collection('emails').countDocuments(matchStage),
            
            db.collection('emails').aggregate([
                ...(Object.keys(matchStage).length ? [{ $match: matchStage }] : []),
                { $group: { _id: '$analytics.esp', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]).toArray(),
            
            db.collection('emails').aggregate([
                ...(Object.keys(matchStage).length ? [{ $match: matchStage }] : []),
                { $group: { _id: '$analytics.sendingDomain', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]).toArray(),
            
            db.collection('emails').aggregate([
                ...(Object.keys(matchStage).length ? [{ $match: matchStage }] : []),
                {
                    $group: {
                        _id: {
                            $dateToString: { 
                                format: '%Y-%m-%d', 
                                date: '$receivedAt' 
                            }
                        },
                        count: { $sum: 1 }
                    }
                },
                { $sort: { _id: -1 } },
                { $limit: 30 }
            ]).toArray(),
            
            db.collection('emails').aggregate([
                { $group: { _id: '$accountId', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]).toArray()
        ]);
        
        res.json({ 
            totalEmails,
            espDistribution: espStats,
            topDomains: domainStats,
            dailyEmailCount: dailyStats,
            emailsByAccount: accountStats
        });
        
    } catch (error) {
        console.error('Error fetching statistics:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});

// --- CORE PROCESSING LOGIC ---

async function processAccountEmails(jobId, accountId) {
    const job = syncJobs[jobId];
    if (!job) return;

    console.log(`[Job: ${jobId}] Starting email processing for account ${accountId}`);

    try {
        await withConnection(accountId, async (connection) => {
            const boxes = await getSelectableMailboxes(connection);
            const boxNames = Object.keys(boxes);
            console.log(`[Job: ${jobId}] Found ${boxNames.length} mailboxes to process.`);

            for (const boxName of boxNames) {
                if (job.status !== 'running') {
                    console.log(`[Job: ${jobId}] Job is no longer running, stopping.`);
                    return;
                }

                job.progress.currentFolder = boxName;
                console.log(`[Job: ${jobId}] Processing folder: ${boxName}`);

                try {
                    await connection.openBox(boxName, true); // Open box in read-only mode

                    // ★★★ FIX: FETCH THE ENTIRE RAW MESSAGE BODY ★★★
                    // This is the crucial change. It gets the full content for parsing.
                    const messages = await connection.search(['ALL'], {
                        bodies: [''], // Fetch the full, raw email body
                        struct: true
                    });

                    job.progress.total += messages.length;
                    console.log(`[Job: ${jobId}] Found ${messages.length} messages in ${boxName}.`);

                    for (const message of messages) {
                        if (job.status !== 'running') return; // Check status again inside loop

                        try {
                            // Pass the full message object to be processed
                            await processMessage(message, accountId);
                            job.progress.processed++;
                        } catch (messageError) {
                            console.error(`[Job: ${jobId}] Failed to process a message in ${boxName}:`, messageError.message);
                            job.progress.errors = (job.progress.errors || 0) + 1;
                        }
                    }
                } catch (boxError) {
                    console.error(`[Job: ${jobId}] Could not process mailbox ${boxName}:`, boxError.message);
                    job.progress.errors = (job.progress.errors || 0) + 1;
                }
            }
        });

        if (job.status === 'running') {
            job.status = 'completed';
            console.log(`✅ [Job: ${jobId}] Email processing completed for account ${accountId}`);
        }
    } catch (error) {
        console.error(`❌ [Job: ${jobId}] CRITICAL FAILURE during email processing:`, error.message);
        job.status = 'failed';
        job.error = error.message;
    }
}


async function processMessage(message, accountId) {
    try {
        const allPart = message.parts.find(part => part.which === '');
        if (!allPart || !allPart.body) {
            console.warn('Message has no processable body part, skipping.');
            return;
        }

        const parsedMail = await simpleParser(allPart.body);

        let messageId = parsedMail.messageId;
        if (!messageId) {
            const uid = message.attributes?.uid || Date.now(); // Use timestamp as fallback
            messageId = `<${uid}.${accountId}.generated@emailsync.local>`;
        }

        const fromAddress = parsedMail.from?.value?.[0]?.address || 'unknown@unknown.com';
        
        const emailDoc = {
            accountId: new ObjectId(accountId),
            messageId: messageId,
            from: fromAddress,
            subject: parsedMail.subject || '(No Subject)',
            body: parsedMail.text || '',
            receivedAt: parsedMail.date || new Date(),
            // ... add other fields you need ...
            createdAt: new Date()
        };

        // 💡 This new log confirms the data before it goes to the database
        console.log(`📦 Preparing to save email: "${emailDoc.subject}" from ${emailDoc.from}`);

        await db.collection('emails').updateOne(
            { messageId: emailDoc.messageId, accountId: emailDoc.accountId },
            { $set: emailDoc },
            { upsert: true }
        );

    } catch (error) {
        console.error('Error in processMessage:', error.message);
        // Re-throw the error so the job handler knows a message failed
        throw error;
    }
}


async function processEmailSync(jobId) {
    const job = syncJobs[jobId];
    if (!job) return;
    
    console.log(`Starting email sync (Job: ${jobId})`);
    
    try {
        await withConnection(job.sourceAccountId, async (sourceConn) => {
            await withConnection(job.destAccountId, async (destConn) => {
                const boxes = await getSelectableMailboxes(sourceConn);
                const boxNames = Object.keys(boxes);
                
                console.log(`Found ${boxNames.length} mailboxes to sync`);
                
                for (const boxName of boxNames) {
                    if (job.status !== 'running') {
                        console.log(`Sync job ${jobId} is no longer running, stopping`);
                        return;
                    }
                    
                    console.log(`Syncing mailbox: ${boxName}`);
                    job.progress.currentFolder = boxName;
                    
                    try {
                        await sourceConn.openBox(boxName, true);
                        
                        // Try to create mailbox on destination (ignore if exists)
                        try {
                            await destConn.addBox(boxName);
                        } catch (e) {
                            // Mailbox likely already exists, continue
                        }
                        
                        const messages = await sourceConn.search(['ALL'], { 
                            bodies: [''], 
                            struct: true 
                        });
                        
                        console.log(`Found ${messages.length} messages to sync in ${boxName}`);
                        job.progress.total += messages.length;
                        
                        for (const message of messages) {
                            if (job.status !== 'running') {
                                console.log(`Sync job ${jobId} paused during processing`);
                                return;
                            }
                            
                            try {
                                const allPart = message.parts.find(part => part.which === '');
                                if (!allPart) continue;
                                
                                const mailBuffer = Buffer.from(allPart.body);
                                const flags = message.attributes?.flags?.filter(f => f !== '\\Recent') || [];
                                const dateHeader = message.attributes?.date || new Date();

                                // Append to destination mailbox
                                await destConn.append(mailBuffer, { 
                                    mailbox: boxName, 
                                    flags, 
                                    date: dateHeader 
                                });

                                // Also process for analytics
                                await processMessage(message, job.sourceAccountId);
                                
                                job.progress.processed++;
                                
                            } catch (messageError) {
                                console.error(`Error syncing message in ${boxName}:`, messageError.message);
                                job.progress.errors = (job.progress.errors || 0) + 1;
                            }
                            
                            // Small delay to prevent overwhelming servers
                            await new Promise(resolve => setTimeout(resolve, 50));
                        }
                        
                    } catch (boxError) {
                        console.error(`Error syncing mailbox ${boxName}:`, boxError.message);
                        job.progress.errors = (job.progress.errors || 0) + 1;
                    }
                }
            });
        });
        
        if (job.status === 'running') {
            job.status = 'completed';
            job.completedAt = new Date();
            console.log(`✓ Email sync completed (Job: ${jobId})`);
        }
        
    } catch (error) {
        console.error(`✗ Email sync failed (Job: ${jobId}):`, error.message);
        job.status = 'failed';
        job.error = error.message;
        job.failedAt = new Date();
    }
}

async function getSelectableMailboxes(connection) {
    try {
        const mailboxes = await connection.getBoxes();
        const selectable = {};
        
        function findSelectable(boxes, prefix = '') {
            for (const name in boxes) {
                const box = boxes[name];
                const path = prefix ? `${prefix}${box.delimiter}${name}` : name;
                
                // Only include selectable mailboxes (not \Noselect)
                if (!box.attribs || !box.attribs.includes('\\Noselect')) {
                    selectable[path] = box;
                }
                
                // Recursively check children
                if (box.children && Object.keys(box.children).length > 0) {
                    findSelectable(box.children, path);
                }
            }
        }
        
        findSelectable(mailboxes);
        return selectable;
        
    } catch (error) {
        console.error('Error getting selectable mailboxes:', error.message);
        throw error;
    }
}

// --- CLEANUP AND START SERVER ---

async function cleanupOldJobs() {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
    
    for (const [jobId, job] of Object.entries(syncJobs)) {
        if (job.createdAt < cutoff && 
            ['completed', 'failed', 'cancelled'].includes(job.status)) {
            delete syncJobs[jobId];
        }
    }
}

// Clean up old jobs every hour
setInterval(cleanupOldJobs, 60 * 60 * 1000);

async function shutdown(signal) {
    console.log(`\nReceived ${signal}. Shutting down gracefully...`);
    
    // Mark all running jobs as cancelled
    for (const job of Object.values(syncJobs)) {
        if (job.status === 'running') {
            job.status = 'cancelled';
            job.error = 'Server shutdown';
        }
    }
    
    // Close all connection pools
    for (const [accountId, pool] of connectionPools.entries()) {
        try {
            console.log(`Closing connection pool for account ${accountId}...`);
            await pool.drain();
            await pool.clear();
        } catch (error) {
            console.error(`Error closing pool for account ${accountId}:`, error.message);
        }
    }
    connectionPools.clear();

    // Close MongoDB connection
    if (mongoClient) {
        try {
            await mongoClient.close();
            console.log("MongoDB connection closed.");
        } catch (error) {
            console.error("Error closing MongoDB connection:", error.message);
        }
    }

    console.log("Graceful shutdown completed.");
    process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGUSR2', () => shutdown('SIGUSR2')); // For nodemon restarts

// Handle uncaught errors
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// --- START APPLICATION ---

async function startApplication() {
    try {
        console.log('🔄 Connecting to MongoDB...');
        mongoClient = await MongoClient.connect(mongoUri);
        db = mongoClient.db();
        
        console.log('🔧 Creating database indexes...');
        await Promise.all([
            // Email indexes
            db.collection('emails').createIndex(
                { messageId: 1, accountId: 1 }, 
                { unique: true, background: true }
            ),
            db.collection('emails').createIndex(
                { accountId: 1 }, 
                { background: true }
            ),
            db.collection('emails').createIndex(
                { from: 1 }, 
                { background: true }
            ),
            db.collection('emails').createIndex(
                { receivedAt: -1 }, 
                { background: true }
            ),
            db.collection('emails').createIndex(
                { subject: 'text', body: 'text' }, 
                { background: true }
            ),
            db.collection('emails').createIndex(
                { 'analytics.esp': 1 }, 
                { background: true }
            ),
            db.collection('emails').createIndex(
                { 'analytics.sendingDomain': 1 }, 
                { background: true }
            ),
            
            // Account indexes
            db.collection('accounts').createIndex(
                { user: 1 }, 
                { unique: true, background: true }
            ),
            db.collection('accounts').createIndex(
                { authStatus: 1 }, 
                { background: true }
            ),
            db.collection('accounts').createIndex(
                { createdAt: -1 }, 
                { background: true }
            )
        ]);
        
        console.log("✅ Connected to MongoDB and created indexes");
        
        // Start the server
        app.listen(port, () => {
            console.log(`🚀 Email Sync & Analytics Hub running on http://localhost:${port}`);
            console.log(`📧 Ready to process emails and sync accounts!`);
            console.log(`🔍 Available endpoints:`);
            console.log(`   • POST /api/accounts - Add manual IMAP account`);
            console.log(`   • GET  /api/auth/google - Google OAuth authentication`);
            console.log(`   • POST /api/process/:accountId - Process account emails`);
            console.log(`   • POST /api/sync/start - Start email sync between accounts`);
            console.log(`   • GET  /api/status - View job status`);
            console.log(`   • GET  /api/emails - View processed emails`);
            console.log(`   • GET  /api/stats - View email statistics`);
        });
        
    } catch (error) {
        console.error("❌ Failed to start application:", error);
        process.exit(1);
    }
}

startApplication();