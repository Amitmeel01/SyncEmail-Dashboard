Email Sync & Analytics Hub
A robust, full-stack application designed to provide a centralized interface for connecting to, synchronizing, and processing emails from multiple IMAP accounts. It offers real-time analytics and a powerful search interface for all processed email content.

✨ Key Features
Multi-Account Connectivity: Simultaneously connect to and manage multiple source and destination IMAP servers.

Robust Connection Handling: Features connection pooling, support for various authentication methods (OAuth2, PLAIN, LOGIN), and graceful management of timeouts and reconnections.

Intelligent Sync:

Automatically detects and recreates folder hierarchies, including those with special characters.

Preserves all essential message flags (\Seen, \Answered, \Flagged, etc.).

Maintains original message dates and headers.

Supports pause and resume capabilities for long-running synchronization tasks.

Real-time Analytics:

Instantly generates analytics on sender, sending domain, and the underlying Email Service Provider (ESP).

Calculates and displays the time delta between when an email was sent and when it was received.

Security Insights:

Checks if the sending mail server is a known open relay.

Verifies if the sending server supports TLS and has a valid certificate.

Full-Text Search: A powerful and responsive search engine for the entire body of all processed emails.

💻 Tech Stack
Tier

Technology

Description

Frontend

React.js + Tailwind CSS

A responsive, single-page application for a seamless user experience.

Backend

Node.js + Express

A powerful backend to handle IMAP operations, data processing, and serving the API.

Database

MongoDB

A NoSQL database chosen for its flexibility and scalability in storing unstructured email and analytics data.

🚀 Getting Started
Follow these instructions to get the project up and running on your local machine for development and testing purposes.

Prerequisites
Ensure you have the following software installed on your system:

Node.js (v18.x or higher recommended)

npm or yarn

MongoDB (running locally or a cloud instance)

Installation & Setup
Clone the repository:

git clone [https://github.com/your-username/email-sync-hub.git](https://github.com/your-username/email-sync-hub.git)
cd email-sync-hub

Backend Setup:

Navigate to the backend directory (assuming server.js is in the root or a /backend folder).

Install dependencies:

npm install

Create a .env file in the same directory and add your configuration:

# Server Configuration
PORT=3001

# MongoDB Connection
MONGO_URI=mongodb://localhost:27017/emailSync

# A secret key for simple data encryption/decryption
SECRET_KEY=your-strong-secret-key

Start the backend server:

node server.js

The server should now be running at http://localhost:3001.

Frontend Setup:

Navigate to the frontend directory (assuming App.jsx is in a /frontend or /client folder).

Install dependencies:

npm install

Start the React development server:

npm start

The application should now be accessible in your browser, typically at http://localhost:3000.

📝 API Endpoints
The backend provides the following RESTful API endpoints:

Method

Endpoint

Description

POST

/api/accounts

Add a new IMAP account to the database.

GET

/api/accounts

Retrieve a list of all configured IMAP accounts.

POST

/api/sync/start

Initiate an email synchronization job.

POST

/api/sync/pause/:jobId

Pause an active synchronization job.

POST

/api/sync/resume/:jobId

Resume a paused synchronization job.

GET

/api/emails

Fetch processed emails with search and pagination.

GET

/api/stats

Get aggregated analytics and statistics.

🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Fork the Project

Create your Feature Branch (git checkout -b feature/AmazingFeature)

Commit your Changes (git commit -m 'Add some AmazingFeature')

Push to the Branch (git push origin feature/AmazingFeature)

Open a Pull Request

📄 License
This project is distributed under the MIT License. See LICENSE for more information.