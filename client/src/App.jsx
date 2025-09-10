import React, { useState, useEffect, useCallback } from 'react';

// --- Icons ---
const Icon = ({ path, className = "w-6 h-6" }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
);

const GoogleIcon = () => (
    <svg className="w-5 h-5 mr-3" viewBox="0 0 48 48">
        <path fill="#FFC107" d="M43.611,20.083H42V20H24v8h11.303c-1.649,4.657-6.08,8-11.303,8c-6.627,0-12-5.373-12-12s5.373-12,12-12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C12.955,4,4,12.955,4,24s8.955,20,20,20s20-8.955,20-20C44,22.659,43.862,21.35,43.611,20.083z"></path>
        <path fill="#FF3D00" d="M6.306,14.691l6.571,4.819C14.655,15.108,18.961,12,24,12c3.059,0,5.842,1.154,7.961,3.039l5.657-5.657C34.046,6.053,29.268,4,24,4C16.318,4,9.656,8.337,6.306,14.691z"></path>
        <path fill="#4CAF50" d="M24,44c5.166,0,9.86-1.977,13.409-5.192l-6.19-5.238C29.211,35.091,26.715,36,24,36c-5.202,0-9.619-3.317-11.283-7.946l-6.522,5.025C9.505,39.556,16.227,44,24,44z"></path>
        <path fill="#1976D2" d="M43.611,20.083H42V20H24v8h11.303c-0.792,2.237-2.231,4.166-4.087,5.571l6.19,5.238C42.012,36.494,44,30.638,44,24C44,22.659,43.862,21.35,43.611,20.083z"></path>
    </svg>
);

// --- Helper Components ---
const StatusBadge = ({ status, type = 'default' }) => {
    const getStatusColor = () => {
        switch (status) {
            case 'running': return 'bg-blue-100 text-blue-800 animate-pulse';
            case 'completed': return 'bg-green-100 text-green-800';
            case 'failed': return 'bg-red-100 text-red-800';
            case 'paused': return 'bg-yellow-100 text-yellow-800';
            default: return 'bg-gray-100 text-gray-800';
        }
    };

    return (
        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor()}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
    );
};

const ProgressBar = ({ current, total, showNumbers = true }) => {
    const percentage = total > 0 ? (current / total) * 100 : 0;
    
    return (
        <div className="w-full">
            <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div 
                    className="bg-gradient-to-r from-blue-500 to-purple-600 h-2.5 rounded-full transition-all duration-500 ease-out" 
                    style={{ width: `${Math.min(percentage, 100)}%` }}
                ></div>
            </div>
            {showNumbers && (
                <div className="flex justify-between text-xs text-gray-500 mt-1">
                    <span>{current.toLocaleString()} processed</span>
                    <span>{total.toLocaleString()} total</span>
                </div>
            )}
        </div>
    );
};

const StatsCard = ({ title, value, subtitle, icon, color = "blue" }) => {
    const colorClasses = {
        blue: "bg-blue-50 border-blue-200 text-blue-800",
        green: "bg-green-50 border-green-200 text-green-800",
        purple: "bg-purple-50 border-purple-200 text-purple-800",
        orange: "bg-orange-50 border-orange-200 text-orange-800"
    };

    return (
        <div className={`p-4 rounded-lg border-2 ${colorClasses[color]}`}>
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-2xl font-bold">{value?.toLocaleString() || '0'}</p>
                    <p className="text-sm font-medium">{title}</p>
                    {subtitle && <p className="text-xs opacity-75">{subtitle}</p>}
                </div>
                {icon && <div className="text-2xl opacity-60">{icon}</div>}
            </div>
        </div>
    );
};

// --- Main App ---
export default function App() {
    const [accounts, setAccounts] = useState([]);
    const [jobs, setJobs] = useState([]);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [emails, setEmails] = useState([]);
    const [stats, setStats] = useState({});
    const [searchTerm, setSearchTerm] = useState('');
    const [filteredEmails, setFilteredEmails] = useState([]);
    const [activeTab, setActiveTab] = useState('dashboard');
    const [isLoading, setIsLoading] = useState(false);
    
    const API_URL = 'https://syncemail-dashboard.onrender.com';

    // --- API Functions ---
    const fetchAccounts = useCallback(async () => {
        try {
            const response = await fetch(`${API_URL}/api/accounts`);
            if (!response.ok) throw new Error('Failed to fetch accounts');
            const data = await response.json();
            setAccounts(data);
        } catch (error) { 
            console.error("Error fetching accounts:", error);
        }
    }, []);
    
const fetchJobStatus = useCallback(async () => {
    try {
        const response = await fetch(`${API_URL}/api/status`);
        if (!response.ok) throw new Error("Failed to fetch jobs");
        const data = await response.json();
        console.log("dd", data);
        setJobs(data);
    } catch (error) {
        console.error("Error fetching job statuses:", error);
    }
}, []); // ✅ no dependency on `emails`

const fetchEmails = useCallback(
    async (showLoader = true) => {
        try {
            if (showLoader) setIsLoading(true);
            const response = await fetch(`${API_URL}/api/emails?limit=100`);
            if (!response.ok) throw new Error("Failed to fetch emails");
            const data = await response.json();
            setEmails(data.emails || []);
        } catch (error) {
            console.error("Error fetching emails:", error);
        } finally {
            if (showLoader) setIsLoading(false);
        }
    },
    [] // ✅ stable
);

const fetchStats = useCallback(async () => {
    try {
        const response = await fetch(`${API_URL}/api/stats`);
        if (!response.ok) throw new Error("Failed to fetch stats");
        const data = await response.json();
        console.log("stt",data)
        setStats(data);
    } catch (error) {
        console.error("Error fetching stats:", error);
    }
}, []);

// --- Effects ---
useEffect(() => {
    // Initial fetch (with loader for emails)
    fetchAccounts();
    fetchEmails(true);
    fetchStats();

    // Background polling (no loader)
    const intervalId = setInterval(() => {
        fetchJobStatus();
        fetchAccounts();
        if (activeTab === "dashboard") {
            fetchStats();
        }
        fetchEmails(false); // ✅ refresh silently without flicker
    }, 3000);

    return () => clearInterval(intervalId);
}, [activeTab, fetchAccounts, fetchJobStatus, fetchEmails, fetchStats]); // ✅ only depends on stable functions + tab


    useEffect(() => {
    // Handle OAuth callback messages
    const handleMessage = (event) => {
        if (event.data === 'oauth_success') {
            fetchAccounts();
        }
    };
    
    window.addEventListener('message', handleMessage);
    
    // Also check URL parameters for OAuth results
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('auth_success') === 'true') {
        alert('Google authentication successful! Your account has been added.');
        fetchAccounts();
        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
    } else if (urlParams.get('error')) {
        alert(`Authentication error: ${decodeURIComponent(urlParams.get('error'))}`);
        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    return () => {
        window.removeEventListener('message', handleMessage);
    };
}, [fetchAccounts]);

    useEffect(() => {
        if (searchTerm === '') {
            setFilteredEmails(emails);
        } else {
            const lowercasedTerm = searchTerm.toLowerCase();
            const filtered = emails.filter(email =>
                email.subject?.toLowerCase().includes(lowercasedTerm) ||
                email.from?.toLowerCase().includes(lowercasedTerm) ||
                email.body?.toLowerCase().includes(lowercasedTerm)
            );
            setFilteredEmails(filtered);
        }
    }, [searchTerm, emails]);

    // --- Event Handlers ---
 const handleAddAccount = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    
    const formData = new FormData(e.target);
    const accountData = Object.fromEntries(formData.entries());
    
    // Fix: Change 'pass' to 'password' to match backend expectation
    if (accountData.pass) {
        accountData.password = accountData.pass;
        delete accountData.pass;
    }
    
    try {
        const response = await fetch(`${API_URL}/api/accounts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(accountData),
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.message);
        
        await fetchAccounts();
        setIsModalOpen(false);
        e.target.reset();
        
        // Show success message
        alert('Account added successfully! You can now process its emails.');
    } catch (err) {
        alert(`Error: ${err.message}`);
    } finally {
        setIsLoading(false);
    }
};

    
    const handleGoogleAuth = () => {
        const authUrl = `${API_URL}/api/auth/google`;
        const popup = window.open(authUrl, '_blank', 'width=500,height=600,noopener,noreferrer');
        setIsModalOpen(false);
        
        // Poll for popup close to refresh accounts
        const pollTimer = setInterval(() => {
            if (popup.closed) {
                clearInterval(pollTimer);
                setTimeout(() => fetchAccounts(), 1000);
            }
        }, 1000);
    };

    const handleProcessAccount = async (accountId) => {
        try {
            const response = await fetch(`${API_URL}/api/process/${accountId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            
            alert('Email processing started! Check the Jobs tab to monitor progress.');
            setActiveTab('jobs');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleStartSync = async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const { sourceAccountId, destAccountId } = Object.fromEntries(formData.entries());
        
        if (sourceAccountId === destAccountId) {
            alert("Source and destination accounts cannot be the same.");
            return;
        }
        
        try {
            const response = await fetch(`${API_URL}/api/sync/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sourceAccountId, destAccountId }),
            });
            
            const data = await response.json();
            if (!response.ok) throw new Error(data.message);
            
            alert('Sync job started! Monitor progress in the Jobs section.');
        } catch (err) { 
            alert(`Error starting sync: ${err.message}`);
        }
    };
    
    const handleJobAction = async (jobId, action) => {
        try {
            const response = await fetch(`${API_URL}/api/sync/${action}/${jobId}`, { 
                method: 'POST' 
            });
            
            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.message);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    // --- Render Functions ---
    const renderDashboard = () => (
        <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatsCard 
                    title="Total Emails" 
                    value={stats.totalEmails} 
                    subtitle="Processed & Analyzed"
                    icon="📧"
                    color="blue"
                />
                <StatsCard 
                    title="Connected Accounts" 
                    value={accounts.length} 
                    subtitle="Email Sources"
                    icon="🔗"
                    color="green"
                />
                <StatsCard 
                    title="Active Jobs" 
                    value={jobs.filter(j => j.status === 'running').length} 
                    subtitle="Processing Now"
                    icon="⚡"
                    color="purple"
                />
                <StatsCard 
                    title="TLS Supported" 
                    value={stats.security?.tlsSupported || 0} 
                    subtitle="Secure Mail Servers"
                    icon="🔒"
                    color="orange"
                />
            </div>

            {/* ESP Distribution */}
            {stats.espDistribution && stats.espDistribution.length > 0 && (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h3 className="text-lg font-semibold mb-4 flex items-center">
                        📊 Email Service Provider Distribution
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {stats.espDistribution.map((esp, index) => (
                            <div key={esp._id} className="p-3 bg-gray-50 rounded-md">
                                <div className="flex justify-between items-center">
                                    <span className="font-medium">{esp._id}</span>
                                    <span className="text-sm text-gray-600">{esp.count}</span>
                                </div>
                                <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                                    <div 
                                        className="bg-blue-500 h-2 rounded-full" 
                                        style={{ width: `${(esp.count / stats.totalEmails) * 100}%` }}
                                    ></div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recent Emails */}
            {stats.recentEmails && stats.recentEmails.length > 0 && (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h3 className="text-lg font-semibold mb-4 flex items-center">
                        ⏰ Recent Email Activity
                    </h3>
                    <div className="space-y-3">
                        {stats.recentEmails.map((email, index) => (
                            <div key={email._id} className="flex items-center justify-between p-3 bg-gray-50 rounded-md">
                                <div className="flex-1">
                                    <p className="font-medium truncate">{email.subject || '(No Subject)'}</p>
                                    <p className="text-sm text-gray-600 truncate">{email.from}</p>
                                </div>
                                <div className="text-right">
                                    <p className="text-xs text-gray-500">
                                        {new Date(email.receivedAt).toLocaleDateString()}
                                    </p>
                                    <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-full">
                                        {email.analytics?.esp || 'Unknown'}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );

    const renderAccounts = () => (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold">Email Accounts</h2>
                <button 
                    onClick={() => setIsModalOpen(true)} 
                    className="bg-indigo-600 text-white font-semibold py-2 px-4 rounded-lg hover:bg-indigo-700 transition-all transform hover:scale-105"
                >
                    Add Account
                </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {accounts.map(account => (
                    <div key={account._id} className="bg-white p-6 rounded-lg shadow-md border-l-4 border-indigo-500">
                        <div className="flex justify-between items-start mb-4">
                            <div className="flex-1">
                                <h3 className="font-semibold text-lg truncate">{account.user}</h3>
                                <p className="text-sm text-gray-600">{account.host}:{account.port}</p>
                                <div className="mt-2">
                                    <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                                        account.authType === 'XOAUTH2' 
                                            ? 'bg-green-100 text-green-800' 
                                            : 'bg-blue-100 text-blue-800'
                                    }`}>
                                        {account.authType === 'XOAUTH2' ? 'OAuth2' : 'Password'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        
                        <div className="space-y-2">
                            <button 
                                onClick={() => handleProcessAccount(account._id)}
                                className="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 transition-colors font-medium"
                            >
                                Process Emails
                            </button>
                            <p className="text-xs text-gray-500 text-center">
                                Click to analyze and process all emails from this account
                            </p>
                        </div>
                    </div>
                ))}
            </div>

            {accounts.length === 0 && (
                <div className="text-center py-12">
                    <div className="text-gray-400 text-6xl mb-4">📧</div>
                    <h3 className="text-xl font-medium text-gray-900 mb-2">No Email Accounts</h3>
                    <p className="text-gray-600 mb-4">Add your first email account to start processing emails</p>
                    <button 
                        onClick={() => setIsModalOpen(true)}
                        className="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition-colors"
                    >
                        Add Account
                    </button>
                </div>
            )}
        </div>
    );

    const renderJobs = () => (
    <div className="space-y-6">
        <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold">Processing Jobs</h2>
            <div className="text-sm text-gray-600">
                Active: {jobs.filter(j => j.status === 'running').length} | 
                Total: {jobs.length}
            </div>
        </div>

        {/* Jobs List with better error handling */}
        <div className="space-y-4">
            {jobs.map(job => (
                <div key={job.id} className="bg-white p-6 rounded-lg shadow-md border-l-4 border-indigo-500">
                    <div className="flex justify-between items-start mb-4">
                        <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                                <h3 className="font-semibold">
                                    {job.type === 'process' ? '📧 Email Processing' : '🔄 Email Sync'} 
                                    <span className="text-gray-500 text-sm ml-2">#{job.id.substring(0, 8)}</span>
                                </h3>
                                <StatusBadge status={job.status} />
                            </div>
                            
                            {job.type === 'sync' ? (
                                <p className="text-sm text-gray-600">
                                    {accounts.find(a => a._id === job.sourceAccountId)?.user || 'Unknown'} 
                                    <span className="mx-2">→</span>
                                    {accounts.find(a => a._id === job.destAccountId)?.user || 'Unknown'}
                                </p>
                            ) : (
                                <p className="text-sm text-gray-600">
                                    Processing: {accounts.find(a => a._id === job.accountId)?.user || 'Unknown'}
                                </p>
                            )}
                            
                            <div className="flex gap-4 text-xs text-gray-500 mt-2">
                                <span>Started: {new Date(job.createdAt).toLocaleString()}</span>
                                {job.duration && (
                                    <span>Duration: {Math.round(job.duration / 1000)}s</span>
                                )}
                            </div>
                        </div>
                        
                        <div className="flex gap-2">
                            {job.status === 'running' && (
                                <button 
                                    onClick={() => handleJobAction(job.id, 'pause')}
                                    className="text-xs bg-yellow-500 text-white font-bold py-1 px-3 rounded hover:bg-yellow-600 transition-colors"
                                >
                                    ⏸ Pause
                                </button>
                            )}
                            {job.status === 'paused' && (
                                <button 
                                    onClick={() => handleJobAction(job.id, 'resume')}
                                    className="text-xs bg-blue-500 text-white font-bold py-1 px-3 rounded hover:bg-blue-600 transition-colors"
                                >
                                    ▶ Resume
                                </button>
                            )}
                        </div>
                    </div>
                    
                    <div className="space-y-3">
                        <ProgressBar 
                            current={job.progress.processed || 0} 
                            total={job.progress.total || 0} 
                        />
                        
                        {job.progress.currentFolder && (
                            <div className="text-xs text-gray-600 bg-gray-50 px-3 py-2 rounded">
                                📁 Current folder: <span className="font-mono">{job.progress.currentFolder}</span>
                            </div>
                        )}
                        
                        {job.progress.errors > 0 && (
                            <div className="text-xs text-orange-600 bg-orange-50 px-3 py-2 rounded">
                                ⚠ {job.progress.errors} errors encountered
                            </div>
                        )}
                        
                        {job.error && (
                            <div className="text-xs text-red-600 bg-red-50 p-3 rounded border border-red-200">
                                <strong>Error:</strong> {job.error}
                            </div>
                        )}
                        
                        {job.status === 'completed' && (
                            <div className="text-xs text-green-600 bg-green-50 px-3 py-2 rounded">
                                ✅ Completed successfully! Processed {job.progress.processed} items.
                            </div>
                        )}
                    </div>
                </div>
            ))}
        </div>

        {jobs.length === 0 && (
            <div className="text-center py-12 bg-white rounded-lg shadow-sm">
                <div className="text-gray-400 text-6xl mb-4">⚡</div>
                <h3 className="text-xl font-medium text-gray-900 mb-2">No Active Jobs</h3>
                <p className="text-gray-600 mb-4">Process emails from your accounts or start a sync job</p>
                <div className="flex justify-center gap-3">
                    <button 
                        onClick={() => setActiveTab('accounts')}
                        className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors"
                    >
                        Go to Accounts
                    </button>
                </div>
            </div>
        )}
    </div>
);

    const renderEmails = () => (
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <h2 className="text-2xl font-bold">Processed Emails</h2>
                <div className="flex items-center gap-4">
                    <input
                        type="text"
                        placeholder="Search emails..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 w-64"
                    />
                    <span className="text-sm text-gray-600">
                        {filteredEmails.length.toLocaleString()} emails
                    </span>
                </div>
            </div>

            {isLoading ? (
                <div className="text-center py-12">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Loading emails...</p>
                </div>
            ) : (
                <div className="bg-white rounded-lg shadow-md overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">From</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ESP</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Received</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {filteredEmails.map(email => (
                                    <tr key={email._id} className="hover:bg-gray-50">
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="text-sm font-medium text-gray-900 truncate max-w-xs">
                                                {email.from}
                                            </div>
                                            <div className="text-xs text-gray-500">
                                                {email.analytics?.sendingDomain}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="text-sm text-gray-900 truncate max-w-xs">
                                                {email.subject || '(No Subject)'}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                                                {email.analytics?.esp || 'Unknown'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-xs">
                                            <div className="flex flex-col gap-1">
                                                {email.analytics?.mailServerSecurity?.supportsTLS && (
                                                    <span className="inline-flex px-2 py-1 text-xs rounded-full bg-green-100 text-green-800">
                                                        TLS ✓
                                                    </span>
                                                )}
                                                {email.analytics?.mailServerSecurity?.hasValidCert && (
                                                    <span className="inline-flex px-2 py-1 text-xs rounded-full bg-green-100 text-green-800">
                                                        Valid Cert ✓
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                            {new Date(email.receivedAt).toLocaleDateString()}
                                            <div className="text-xs">
                                                {new Date(email.receivedAt).toLocaleTimeString()}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {filteredEmails.length === 0 && (
                        <div className="text-center py-12">
                            <div className="text-gray-400 text-6xl mb-4">📬</div>
                            <h3 className="text-xl font-medium text-gray-900 mb-2">No Emails Found</h3>
                            <p className="text-gray-600">
                                {searchTerm ? 'Try adjusting your search terms' : 'Process some email accounts to see results here'}
                            </p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );

    // --- Main Render ---
    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
            {/* Header */}
            <header className="bg-white shadow-sm border-b border-gray-200">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center py-4">
                        <div className="flex items-center space-x-4">
                            <div className="text-2xl font-bold text-indigo-600">📧 EmailSync Pro</div>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="hidden md:flex items-center space-x-2 text-sm text-gray-600">
                                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                                <span>Live Dashboard</span>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                {/* Navigation Tabs */}
                <div className="mb-8">
                    <nav className="flex space-x-8 border-b border-gray-200">
                        {[
                            { key: 'dashboard', label: 'Dashboard', icon: '📊' },
                            { key: 'accounts', label: 'Accounts', icon: '👤' },
                            { key: 'jobs', label: 'Jobs', icon: '⚡' },
                            { key: 'emails', label: 'Emails', icon: '📧' }
                        ].map(tab => (
                            <button
                                key={tab.key}
                                onClick={() => setActiveTab(tab.key)}
                                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                                    activeTab === tab.key
                                        ? 'border-indigo-500 text-indigo-600'
                                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                }`}
                            >
                                <span className="flex items-center space-x-2">
                                    <span>{tab.icon}</span>
                                    <span>{tab.label}</span>
                                </span>
                            </button>
                        ))}
                    </nav>
                </div>

                {/* Tab Content */}
                <main>
                    {activeTab === 'dashboard' && renderDashboard()}
                    {activeTab === 'accounts' && renderAccounts()}
                    {activeTab === 'jobs' && renderJobs()}
                    {activeTab === 'emails' && renderEmails()}
                </main>
            </div>

            {/* Add Account Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                    <div className="bg-white rounded-lg max-w-md w-full max-h-[90vh] overflow-y-auto">
                        <div className="p-6">
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-lg font-semibold">Add Email Account</h3>
                                <button 
                                    onClick={() => setIsModalOpen(false)}
                                    className="text-gray-400 hover:text-gray-600 text-2xl"
                                >
                                    ×
                                </button>
                            </div>

                            {/* Google OAuth Button */}
                            <div className="mb-6">
                                <button 
                                    onClick={handleGoogleAuth}
                                    className="w-full flex items-center justify-center py-3 px-4 border border-gray-300 rounded-lg bg-white hover:bg-gray-50 transition-colors"
                                >
                                    <GoogleIcon />
                                    Sign in with Google
                                </button>
                                <p className="text-xs text-gray-500 mt-2 text-center">
                                    Recommended: Secure OAuth2 authentication
                                </p>
                            </div>

                            <div className="relative mb-6">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-gray-300"></div>
                                </div>
                                <div className="relative flex justify-center text-sm">
                                    <span className="px-2 bg-white text-gray-500">Or add manually</span>
                                </div>
                            </div>

                            {/* Manual Account Form */}
                            <form onSubmit={handleAddAccount} className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                        Email Address
                                    </label>
                                    <input 
                                        type="email" 
                                        name="user" 
                                        required 
                                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                                        placeholder="your.email@example.com"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                        Password
                                    </label>
                                   <input 
    type="password" 
    name="password"  // ✅ Correct - matches backend
    required 
    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
    placeholder="App password or regular password"
/>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                            IMAP Server
                                        </label>
                                        <input 
                                            type="text" 
                                            name="host" 
                                            required 
                                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                                            placeholder="imap.gmail.com"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-700 mb-1">
                                            Port
                                        </label>
                                        <input 
                                            type="number" 
                                            name="port" 
                                            required 
                                            defaultValue="993"
                                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                                        />
                                    </div>
                                </div>

                                <div className="flex items-center">
                                    <input 
                                        type="checkbox" 
                                        name="tls" 
                                        defaultChecked 
                                        className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                    />
                                    <label className="ml-2 block text-sm text-gray-900">
                                        Use TLS/SSL (Recommended)
                                    </label>
                                </div>

                                <div className="bg-blue-50 p-3 rounded-md">
                                    <h4 className="text-sm font-medium text-blue-900 mb-2">Common Settings:</h4>
                                    <div className="text-xs text-blue-800 space-y-1">
                                        <div><strong>Gmail:</strong> imap.gmail.com:993</div>
                                        <div><strong>Outlook:</strong> outlook.office365.com:993</div>
                                        <div><strong>Yahoo:</strong> imap.mail.yahoo.com:993</div>
                                    </div>
                                </div>

                                <div className="flex gap-3 pt-4">
                                    <button 
                                        type="button" 
                                        onClick={() => setIsModalOpen(false)}
                                        className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        type="submit" 
                                        disabled={isLoading}
                                        className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors disabled:opacity-50"
                                    >
                                        {isLoading ? 'Adding...' : 'Add Account'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}

            {/* Footer */}
            <footer className="bg-white border-t border-gray-200 mt-12">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div className="flex justify-between items-center text-sm text-gray-600">
                        <div>
                            EmailSync Pro - Advanced Email Processing & Analytics
                        </div>
                        <div className="flex items-center space-x-4">
                            <span>API Status: </span>
                            <div className="flex items-center space-x-1">
                                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                                <span>Connected</span>
                            </div>
                        </div>
                    </div>
                </div>
            </footer>
        </div>
    );
}
                        