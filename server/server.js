
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
const mongoUri = process.env.MONGO_URI

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
const syncJobs = {};
const connectionPools = new Map();

// --- ENCRYPTION HELPERS ---
const encrypt = (text) => Buffer.from(text).toString('base64');
const decrypt = (text) => Buffer.from(text, 'base64').toString('ascii');

// --- ENHANCED IMAP CONNECTION POOL ---
async function refreshOAuth2Token(account) {
    try {
        console.log(`Refreshing OAuth2 token for ${account.user}`);
        
        if (!account.refreshToken) {
            throw new Error('No refresh token available');
        }
        
        oauth2Client.setCredentials({ 
            refresh_token: account.refreshToken 
        });
        
        const { credentials } = await oauth2Client.refreshAccessToken();
        
        if (!credentials.access_token) {
            throw new Error('Failed to get new access token');
        }
        
        // Update account with new token
        const updatedAccount = {
            ...account,
            accessToken: credentials.access_token,
            tokenExpiry: new Date(credentials.expiry_date || Date.now() + 3600000) // 1 hour default
        };
        
        await db.collection('accounts').updateOne(
            { _id: account._id },
            { 
                $set: { 
                    accessToken: credentials.access_token,
                    tokenExpiry: new Date(credentials.expiry_date || Date.now() + 3600000)
                }
            }
        );
        
        console.log(`✓ Token refreshed successfully for ${account.user}`);
        return updatedAccount;
        
    } catch (error) {
        console.error(`✗ Failed to refresh token for ${account.user}:`, error.message);
        throw new Error(`Token refresh failed: ${error.message}`);
    }
}

function createPoolForAccount(account) {
    if (connectionPools.has(account._id.toString())) {
        return connectionPools.get(account._id.toString());
    }

    const factory = {
        create: async () => {
            console.log(`Creating connection for ${account.user}`);
            
            // For OAuth2 accounts, ensure token is valid
            if (account.authType === 'XOAUTH2') {
                // Check if token needs refresh (refresh 5 minutes before expiry)
                const now = new Date();
                const tokenExpiry = new Date(account.tokenExpiry);
                const refreshThreshold = new Date(tokenExpiry.getTime() - 5 * 60 * 1000); // 5 minutes before expiry
                
                if (now >= refreshThreshold) {
                    try {
                        account = await refreshOAuth2Token(account);
                    } catch (error) {
                        console.error(`Cannot refresh token for ${account.user}, marking account as invalid`);
                        // Mark account as having authentication issues
                        await db.collection('accounts').updateOne(
                            { _id: account._id },
                            { $set: { authStatus: 'invalid', lastError: error.message, updatedAt: new Date() } }
                        );
                        throw error;
                    }
                }
            }

            const config = {
                imap: {
                    host: account.host,
                    port: account.port,
                    tls: true,
                    authTimeout: 30000,
                    connTimeout: 30000,
                    tlsOptions: { 
                        rejectUnauthorized: false,
                        servername: account.host
                    }
                }
            };

            if (account.authType === 'XOAUTH2') {
                if (!account.accessToken) {
                    throw new Error('No access token available for OAuth2 authentication');
                }
                config.imap.xoauth2 = account.accessToken;
                config.imap.user = account.user;
            } else {
                config.imap.user = account.user;
                config.imap.password = decrypt(account.password);
            }

            try {
                const connection = await imaps.connect(config);
                
                // Mark account as working
                await db.collection('accounts').updateOne(
                    { _id: account._id },
                    { $set: { authStatus: 'valid', lastError: null, updatedAt: new Date() } }
                );
                
                console.log(`✓ Connection established for ${account.user}`);
                return connection;
                
            } catch (error) {
                console.error(`✗ Failed to create connection for ${account.user}:`, error.message);
                
                // Mark account as having issues
                await db.collection('accounts').updateOne(
                    { _id: account._id },
                    { $set: { authStatus: 'error', lastError: error.message, updatedAt: new Date() } }
                );
                
                throw error;
            }
        },
        destroy: async (connection) => {
            try {
                if (connection && typeof connection.end === 'function') {
                    connection.end();
                }
            } catch (error) {
                console.error('Error destroying connection:', error);
            }
        }
    };

    const pool = genericPool.createPool(factory, {
        min: 0, // Don't maintain minimum connections for problematic accounts
        max: 2, // Reduced max to avoid overwhelming server
        acquireTimeoutMillis: 45000,
        createTimeoutMillis: 45000,
        destroyTimeoutMillis: 5000,
        idleTimeoutMillis: 300000,
        reapIntervalMillis: 1000,
        autostart: false,
        // Add validation to check if connections are still valid
        testOnBorrow: true
    });

    // Add error handling for the pool
    pool.on('factoryCreateError', (err) => {
        console.error(`Pool factory error for account ${account._id}:`, err.message);
    });

    pool.on('factoryDestroyError', (err) => {
        console.error(`Pool destroy error for account ${account._id}:`, err.message);
    });

    connectionPools.set(account._id.toString(), pool);
    return pool;
}


async function withConnection(accountId, callback, maxRetries = 1) {
    let lastError;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            const account = await db.collection('accounts').findOne({ _id: new ObjectId(accountId) });
            if (!account) throw new Error("Account not found");

            // Check if account is marked as invalid
            if (account.authStatus === 'invalid') {
                throw new Error(`Account ${account.user} has invalid authentication. Please re-authenticate.`);
            }

            const pool = createPoolForAccount(account);
            let connection;
            
            try {
                connection = await pool.acquire();
                return await callback(connection);
            } finally {
                if (connection) {
                    pool.release(connection);
                }
            }
        } catch (error) {
            lastError = error;
            console.error(`Connection attempt ${attempt + 1} failed:`, error.message);
            
            if (attempt === maxRetries) {
                throw error;
            }
            
            // Wait before retry
            await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
        }
    }
    
    throw lastError;
}

// --- EMAIL ANALYTICS FUNCTIONS ---
async function detectESP(fromAddress, headers) {
    const domain = fromAddress.split('@')[1];
    const espPatterns = {
        'Gmail': ['gmail.com', 'googlemail.com'],
        'Outlook': ['outlook.com', 'hotmail.com', 'live.com'],
        'Yahoo': ['yahoo.com', 'ymail.com'],
        'Amazon SES': ['amazonses.com'],
        'SendGrid': ['sendgrid.net'],
        'Mailchimp': ['mailchimp.com'],
        'Constant Contact': ['constantcontact.com']
    };

    // Check domain patterns
    for (const [esp, domains] of Object.entries(espPatterns)) {
        if (domains.some(d => domain.includes(d))) {
            return esp;
        }
    }

    // Check headers for ESP signatures
    const receivedHeaders = headers.received || [];
    for (const received of receivedHeaders) {
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
        // Get MX records
        const mxRecords = await dns.resolveMx(domain);
        if (!mxRecords || mxRecords.length === 0) {
            return { hasValidMX: false, supportsTLS: false, hasValidCert: false, isOpenRelay: false };
        }

        const primaryMX = mxRecords.sort((a, b) => a.priority - b.priority)[0];
        const mxHost = primaryMX.exchange;

        // Check TLS support and certificate
        const tlsResult = await new Promise((resolve) => {
            const socket = tls.connect(587, mxHost, { 
                rejectUnauthorized: false,
                timeout: 5000 
            });
            
            socket.on('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve({
                    supportsTLS: true,
                    hasValidCert: !socket.authorized ? false : true,
                    certInfo: cert
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

        // Basic open relay check (simplified)
        const isOpenRelay = false; // This would require more complex SMTP testing

        return {
            hasValidMX: true,
            mxHost: mxHost,
            supportsTLS: tlsResult.supportsTLS,
            hasValidCert: tlsResult.hasValidCert,
            isOpenRelay: isOpenRelay
        };
    } catch (error) {
        console.error(`Error checking mail server security for ${domain}:`, error);
        return { hasValidMX: false, supportsTLS: false, hasValidCert: false, isOpenRelay: false };
    }
}

// --- API ENDPOINTS ---

// OAuth2 Authentication
app.get('/api/auth/google', (req, res) => {
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['https://mail.google.com/'],
    });
    res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code, state } = req.query; // state contains accountId for re-auth
    const frontendUrl = "https://sync-email-dashboard.vercel.app/";

    if (req.query.error) {
        console.error('Google Auth Error:', req.query.error);
        return res.redirect(`${frontendUrl}?error=auth_denied`);
    }

    if (!code) {
        return res.redirect(`${frontendUrl}?error=missing_code`);
    }

    try {
        const { tokens } = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const profile = await gmail.users.getProfile({ userId: 'me' });
        const userEmail = profile.data.emailAddress;

        if (!userEmail) {
            return res.redirect(`${frontendUrl}?error=email_not_found`);
        }

        const accountData = {
            host: 'imap.gmail.com',
            port: 993,
            user: userEmail,
            authType: 'XOAUTH2',
            refreshToken: tokens.refresh_token,
            accessToken: tokens.access_token,
            tokenExpiry: new Date(tokens.expiry_date),
            authStatus: 'valid',
            lastError: null,
            password: null,
            updatedAt: new Date()
        };

        if (state) {
            // This is a re-authentication for existing account
            await db.collection('accounts').updateOne(
                { _id: new ObjectId(state) },
                { $set: accountData }
            );
        } else {
            // New account
            await db.collection('accounts').updateOne(
                { user: userEmail },
                { 
                    $set: accountData, 
                    $setOnInsert: { createdAt: new Date() } 
                },
                { upsert: true }
            );
        }

        res.redirect(`${frontendUrl}?success=true`);

    } catch (error) {
        console.error('Error during Google OAuth callback:', error);
        const errorMessage = error.response?.data?.error || 'authentication_failed';
        res.redirect(`${frontendUrl}?error=${errorMessage}`);
    }
});

// Account Management
app.post('/api/accounts', async (req, res) => {
    const { host, port, user, password, authType = 'PLAIN' } = req.body;
    
    try {
        // Test connection before saving
        const testConfig = {
            imap: {
                host,
                port: parseInt(port, 10),
                tls: true,
                authTimeout: 10000,
                user,
                password,
                tlsOptions: { rejectUnauthorized: false }
            }
        };
        
        const testConnection = await imaps.connect(testConfig);
        testConnection.end();

        const newAccount = {
            host,
            port: parseInt(port, 10),
            user,
            password: encrypt(password),
            authType,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await db.collection('accounts').insertOne(newAccount);
        res.status(201).json({ 
            message: 'Account added successfully', 
            accountId: result.insertedId 
        });
    } catch (error) {
        console.error('Error adding account:', error);
        if (error.code === 11000) {
            res.status(409).json({ message: "Account already exists" });
        } else {
            res.status(400).json({ message: `Connection failed: ${error.message}` });
        }
    }
});

app.post('/api/accounts/:accountId/reauth', async (req, res) => {
    const { accountId } = req.params;
    
    try {
        const account = await db.collection('accounts').findOne({ _id: new ObjectId(accountId) });
        if (!account) {
            return res.status(404).json({ message: 'Account not found' });
        }

        if (account.authType === 'XOAUTH2') {
            // For OAuth2, redirect to re-authentication
            const url = oauth2Client.generateAuthUrl({
                access_type: 'offline',
                prompt: 'consent',
                scope: ['https://mail.google.com/'],
                state: accountId // Pass account ID to identify which account to update
            });
            res.json({ authUrl: url });
        } else {
            // For regular accounts, test connection
            const testConfig = {
                imap: {
                    host: account.host,
                    port: account.port,
                    tls: true,
                    authTimeout: 10000,
                    user: account.user,
                    password: decrypt(account.password),
                    tlsOptions: { rejectUnauthorized: false }
                }
            };
            
            const testConnection = await imaps.connect(testConfig);
            testConnection.end();

            await db.collection('accounts').updateOne(
                { _id: account._id },
                { $set: { authStatus: 'valid', lastError: null, updatedAt: new Date() } }
            );

            res.json({ message: 'Account authentication verified' });
        }
    } catch (error) {
        console.error('Error during re-authentication:', error);
        res.status(500).json({ message: `Re-authentication failed: ${error.message}` });
    }
});


app.get('/api/accounts', async (req, res) => {
    try {
        const accounts = await db.collection('accounts').find(
            {},
            { projection: { password: 0, refreshToken: 0, accessToken: 0 } }
        ).toArray();
        res.json(accounts);
    } catch (error) {
        console.error('Error fetching accounts:', error);
        res.status(500).json({ message: 'Failed to fetch accounts' });
    }
});

// Process Single Account (New endpoint)
app.post('/api/process/:accountId', async (req, res) => {
    const { accountId } = req.params;
    
    try {
        const account = await db.collection('accounts').findOne({ _id: new ObjectId(accountId) });
        if (!account) {
            return res.status(404).json({ message: 'Account not found' });
        }

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

        // Start processing in background
        processAccountEmails(jobId, accountId).catch(err => {
            console.error(`Process job ${jobId} failed:`, err);
            syncJobs[jobId].status = 'failed';
            syncJobs[jobId].error = err.message;
        });

        res.status(202).json({ message: 'Email processing started', jobId });
    } catch (error) {
        console.error('Error starting email processing:', error);
        res.status(500).json({ message: 'Failed to start processing' });
    }
});

// Sync Between Accounts
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

        // Start sync in background
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

// Job Management
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
    if (syncJobs[jobId] && syncJobs[jobId].status === 'paused') {
        syncJobs[jobId].status = 'running';
        
        if (syncJobs[jobId].type === 'process') {
            processAccountEmails(jobId, syncJobs[jobId].accountId).catch(err => {
                console.error(`Process job ${jobId} failed on resume:`, err);
                syncJobs[jobId].status = 'failed';
                syncJobs[jobId].error = err.message;
            });
        } else {
            processEmailSync(jobId).catch(err => {
                console.error(`Sync job ${jobId} failed on resume:`, err);
                syncJobs[jobId].status = 'failed';
                syncJobs[jobId].error = err.message;
            });
        }
        
        res.json({ message: 'Job resumed' });
    } else {
        res.status(404).json({ message: 'Job not found or not paused' });
    }
});

app.get('/api/sync/status', (req, res) => {
    res.json(Object.values(syncJobs));
});

// Email Data
app.get('/api/emails', async (req, res) => {
    try {
        const { search, limit = 50, skip = 0 } = req.query;
        let query = {};
        
        if (search) {
            query = {
                $or: [
                    { from: { $regex: search, $options: 'i' } },
                    { subject: { $regex: search, $options: 'i' } },
                    { body: { $regex: search, $options: 'i' } }
                ]
            };
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
        const [
            totalEmails,
            espStats,
            domainStats,
            securityStats,
            recentEmails
        ] = await Promise.all([
            db.collection('emails').countDocuments(),
            db.collection('emails').aggregate([
                { $group: { _id: '$analytics.esp', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]).toArray(),
            db.collection('emails').aggregate([
                { $group: { _id: '$analytics.sendingDomain', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]).toArray(),
            db.collection('emails').aggregate([
                {
                    $group: {
                        _id: null,
                        tlsSupported: { $sum: { $cond: ['$analytics.mailServerSecurity.supportsTLS', 1, 0] } },
                        validCerts: { $sum: { $cond: ['$analytics.mailServerSecurity.hasValidCert', 1, 0] } },
                        openRelays: { $sum: { $cond: ['$analytics.mailServerSecurity.isOpenRelay', 1, 0] } }
                    }
                }
            ]).toArray(),
            db.collection('emails').find().sort({ receivedAt: -1 }).limit(5).toArray()
        ]);

        res.json({
            totalEmails,
            espDistribution: espStats,
            topDomains: domainStats,
            security: securityStats[0] || { tlsSupported: 0, validCerts: 0, openRelays: 0 },
            recentEmails
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});

// --- CORE PROCESSING LOGIC ---

async function processAccountEmails(jobId, accountId) {
    const job = syncJobs[jobId];
    if (!job) return;

    console.log(`[${jobId}] Starting email processing for account ${accountId}`);
    
    try {
        await withConnection(accountId, async (connection) => {
            const boxes = await getSelectableMailboxes(connection);
            const boxNames = Object.keys(boxes);
            
            console.log(`[${jobId}] Found ${boxNames.length} mailboxes to process`);
            
            for (const boxName of boxNames) {
                if (job.status !== 'running') {
                    console.log(`[${jobId}] Job paused at ${boxName}`);
                    return;
                }
                
                job.progress.currentFolder = boxName;
                console.log(`[${jobId}] Processing folder: ${boxName}`);
                
                await connection.openBox(boxName, true);
                const messages = await connection.search(['ALL'], { 
                    bodies: ['HEADER', 'TEXT', ''], 
                    struct: true 
                });
                
                job.progress.total += messages.length;
                console.log(`[${jobId}] Found ${messages.length} messages in ${boxName}`);
                
                for (const message of messages) {
                    if (job.status !== 'running') {
                        console.log(`[${jobId}] Job paused during message processing`);
                        return;
                    }
                    
                    try {
                        await processMessage(message, accountId);
                        job.progress.processed++;
                        
                        // Log progress every 10 messages
                        if (job.progress.processed % 10 === 0) {
                            console.log(`[${jobId}] Processed ${job.progress.processed}/${job.progress.total} emails`);
                        }
                    } catch (error) {
                        console.error(`[${jobId}] Error processing message:`, error);
                        // Continue with next message
                    }
                }
            }
        });
        
        if (job.status === 'running') {
            job.status = 'completed';
            console.log(`[${jobId}] Email processing completed successfully`);
        }
        
    } catch (error) {
        console.error(`[${jobId}] Email processing failed:`, error);
        job.status = 'failed';
        job.error = error.message;
    }
}

async function processMessage(message, accountId) {
    try {
        const allPart = message.parts.find(part => part.which === '');
        if (!allPart) return;
        
        const mailBuffer = Buffer.from(allPart.body, 'binary');
        const parsedMail = await simpleParser(mailBuffer);
        
        if (!parsedMail.messageId) return; // Skip messages without message ID
        
        const fromAddress = parsedMail.from?.value?.[0]?.address || 'unknown@unknown.com';
        const sendingDomain = fromAddress.split('@')[1] || 'unknown.com';
        
        // Generate analytics
        const esp = await detectESP(fromAddress, parsedMail.headers);
        const mailServerSecurity = await checkMailServerSecurity(sendingDomain);
        
        // Calculate sent-received delta
        const sentDate = parsedMail.date || message.attributes.date;
        const receivedDate = message.attributes.date || new Date();
        const sentReceivedDelta = sentDate ? 
            Math.round((receivedDate.getTime() - sentDate.getTime()) / 1000) : null;
        
        const emailData = {
            accountId: new ObjectId(accountId),
            messageId: parsedMail.messageId,
            from: fromAddress,
            to: parsedMail.to?.text || '',
            subject: parsedMail.subject || '(No Subject)',
            body: parsedMail.text || parsedMail.html || '',
            receivedAt: receivedDate,
            sentAt: sentDate,
            flags: message.flags || [],
            analytics: {
                sendingDomain,
                esp,
                sentReceivedDelta,
                mailServerSecurity
            },
            createdAt: new Date(),
            updatedAt: new Date()
        };
        
        // Upsert email (avoid duplicates)
        await db.collection('emails').updateOne(
            { messageId: emailData.messageId },
            { $set: emailData },
            { upsert: true }
        );
        
    } catch (error) {
        console.error('Error processing individual message:', error);
        throw error;
    }
}

async function processEmailSync(jobId) {
    const job = syncJobs[jobId];
    if (!job) return;

    console.log(`[${jobId}] Starting email sync between accounts`);
    
    try {
        await withConnection(job.sourceAccountId, async (sourceConn) => {
            await withConnection(job.destAccountId, async (destConn) => {
                const boxes = await getSelectableMailboxes(sourceConn);
                const boxNames = Object.keys(boxes);
                
                for (const boxName of boxNames) {
                    if (job.status !== 'running') return;
                    
                    job.progress.currentFolder = boxName;
                    console.log(`[${jobId}] Syncing folder: ${boxName}`);
                    
                    await sourceConn.openBox(boxName, true);
                    
                    // Create destination folder if it doesn't exist
                    try {
                        await destConn.addBox(boxName);
                    } catch (e) {
                        // Folder likely exists, continue
                    }
                    
                    const messages = await sourceConn.search(['ALL'], {
                        bodies: [''],
                        struct: true
                    });
                    
                    job.progress.total += messages.length;
                    
                    for (const message of messages) {
                        if (job.status !== 'running') return;
                        
                        try {
                            const allPart = message.parts.find(part => part.which === '');
                            const mailBuffer = Buffer.from(allPart.body, 'binary');
                            
                            const flags = message.flags.filter(f => f !== '\\Recent');
                            const dateHeader = message.attributes.date;
                            
                            await destConn.append(mailBuffer, {
                                mailbox: boxName,
                                flags,
                                date: dateHeader
                            });
                            
                            // Also process for analytics
                            await processMessage(message, job.sourceAccountId);
                            
                            job.progress.processed++;
                        } catch (error) {
                            console.error(`[${jobId}] Error syncing message:`, error);
                            // Continue with next message
                        }
                    }
                }
            });
        });
        
        if (job.status === 'running') {
            job.status = 'completed';
            console.log(`[${jobId}] Email sync completed successfully`);
        }
        
    } catch (error) {
        console.error(`[${jobId}] Email sync failed:`, error);
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
process.on('SIGTERM', async () => {
    console.log('Shutting down gracefully...');
    // Close all connection pools
    for (const [accountId, pool] of connectionPools) {
        try {
            await pool.drain();
            await pool.clear();
        } catch (error) {
            console.error(`Error closing pool for account ${accountId}:`, error);
        }
    }
    process.exit(0);
});

MongoClient.connect(mongoUri)
    .then(async (client) => {
        db = client.db();
        
        // Create indexes
        await Promise.all([
            db.collection('emails').createIndex({ messageId: 1 }, { unique: true }),
            db.collection('emails').createIndex({ from: 1 }),
            db.collection('emails').createIndex({ subject: 'text', body: 'text' }),
            db.collection('emails').createIndex({ receivedAt: -1 }),
            db.collection('emails').createIndex({ 'analytics.sendingDomain': 1 }),
            db.collection('emails').createIndex({ 'analytics.esp': 1 }),
            db.collection('accounts').createIndex({ user: 1 }, { unique: true })
        ]);
        
        console.log("✓ Connected to MongoDB and created indexes");
        
        app.listen(port, () => {
            console.log(`🚀 Email Sync & Analytics Hub running on http://localhost:${port}`);
        });
    })
    .catch(console.error);