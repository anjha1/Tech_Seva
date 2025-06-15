const express = require('express');
const fs = require('fs');
const fsp = require('fs').promises; // For asynchronous file operations
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 3000; // Define PORT here, from .env or default to 3000

// === IMPORTANT NOTE FOR RENDER DEPLOYMENT ===
// Render's free tier uses an ephemeral filesystem.
// This means any data written to files (like users.json and jobs.json)
// will be DELETED every time your server restarts (which happens frequently).
//
// For persistent data on Render, you MUST use a dedicated database service
// like MongoDB Atlas, PostgreSQL, or Render's own managed databases.
//
// For this demonstration, 'users' and 'jobs' data will be stored in local JSON files.
// This data will persist when running LOCALLY but will be lost on every server restart
// when deployed on Render's ephemeral filesystem.

// === Create data directory if it doesn't exist ===
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log('Created data directory.');
}

// === File paths for JSON data storage ===
const USERS_JSON = path.join(dataDir, 'users.json');
const JOBS_JSON = path.join(dataDir, 'jobs.json');

// === Initialize Data Files (ensure they exist with empty arrays if not present) ===
async function initializeDataFiles() {
    try {
        await fsp.access(USERS_JSON);
    } catch (e) {
        if (e.code === 'ENOENT') {
            await fsp.writeFile(USERS_JSON, '[]', 'utf8');
            console.log('Created empty users.json');
        } else {
            console.error('Error checking users.json for existence:', e);
        }
    }
    try {
        await fsp.access(JOBS_JSON);
    } catch (e) {
        if (e.code === 'ENOENT') {
            await fsp.writeFile(JOBS_JSON, '[]', 'utf8');
            console.log('Created empty jobs.json');
        } else {
            console.error('Error checking jobs.json for existence:', e);
        }
    }
}
initializeDataFiles(); // Call this once when the server starts

// === Middleware Setup ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session management middleware setup.
app.use(session({
    secret: process.env.SESSION_SECRET || 'a_very_long_random_secret_for_session_management', // ⚠️ IMPORTANT: Use environment variable
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (requires HTTPS)
        maxAge: 24 * 60 * 60 * 1000 // Session lasts for 24 hours
    }
}));

// === Email Transporter Setup for Nodemailer ===
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // ⚠️ IMPORTANT: Get from environment variable
        pass: process.env.EMAIL_PASS // ⚠️ IMPORTANT: Get from environment variable (App password for Gmail)
    }
});

// === In-memory OTP Store (OTPs are temporary by nature, no file persistence needed) ===
const otpStore = {}; // Stores OTPs: email -> { otp, expiresAt }

// === OTP Generator Function ===
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// === Helper Functions for Data Persistence (reading and writing JSON files) ===

async function readUsers() {
    try {
        const data = await fsp.readFile(USERS_JSON, 'utf8');
        return data.trim() ? JSON.parse(data) : [];
    } catch (error) {
        if (error.code === 'ENOENT') {
            return []; // File not found, return empty array (should be initialized by now)
        }
        console.error('CRITICAL ERROR reading users.json:', error.message);
        throw new Error('Failed to read user data due to file error or invalid JSON.');
    }
}

async function writeUsers(users) {
    try {
        await fsp.writeFile(USERS_JSON, JSON.stringify(users, null, 2), 'utf8');
    } catch (error) {
        console.error('CRITICAL ERROR writing users.json:', error.message);
        throw new Error('Failed to write user data due to file error.');
    }
}

async function readJobs() {
    try {
        const data = await fsp.readFile(JOBS_JSON, 'utf8');
        return data.trim() ? JSON.parse(data) : [];
    } catch (error) {
        if (error.code === 'ENOENT') {
            return []; // File not found, return empty array (should be initialized by now)
        }
        console.error('CRITICAL ERROR reading jobs.json:', error.message);
        throw new Error('Failed to read job data due to file error or invalid JSON.');
    }
}

async function writeJobs(jobs) {
    try {
        await fsp.writeFile(JOBS_JSON, JSON.stringify(jobs, null, 2), 'utf8');
    } catch (error) {
        console.error('CRITICAL ERROR writing jobs.json:', error.message);
        throw new Error('Failed to write job data due to file error.');
    }
}

async function sendEmailOTP(email, otp) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.error('Email credentials not set in environment variables. OTP email will not be sent.');
        return false;
    }
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER, // Use environment variable
            to: email,
            subject: 'Your TechSeva OTP',
            html: `<p>Your One-Time Password (OTP) for TechSeva is: <strong>${otp}</strong></p><p>This OTP is valid for 5 minutes.</p>`
        });
        return true;
    } catch (err) {
        console.error('Email sending failed:', err);
        return false;
    }
}

// === Middleware for Authentication Protection ===
// Modified to differentiate between HTML page requests and API requests
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.id) {
        next();
    } else {
        // If client expects HTML (e.g., a direct page request like /technician.html), redirect to login page.
        // This prevents the browser from trying to parse a JSON error as HTML.
        if (req.accepts('html')) {
            res.redirect('/');
        } else {
            // For API requests expecting JSON, send a JSON unauthorized response.
            res.status(401).json({ success: false, message: 'Unauthorized. Please login.', redirect: '/' });
        }
    }
}

// === Routes ===

// Serve specific HTML files WITH authentication and role checks FIRST
// Order matters: specific protected routes before general static serving
// app.get('/user', isAuthenticated, (req, res) => {
//     if (req.session.user.role === 'user' || req.session.user.role === 'admin') {
//         res.sendFile(path.join(__dirname, 'views', 'user.html'));
//     } else {
//         res.status(403).send('Access Denied: You do not have permission to view this page.');
//     }
// });

// app.get('/technician', isAuthenticated, (req, res) => {
//     // isAuthenticated middleware already handles the redirect for HTML requests if not authenticated
//     if (req.session.user.role === 'technician' || req.session.user.role === 'admin') {
//         res.sendFile(path.join(__dirname, 'views', 'technician.html'));
//     } else {
//         // If isAuthenticated didn't redirect (e.g., due to role mismatch), send 403.
//         // This line is mostly for clarity; isAuthenticated handles actual unauthenticated access.
//         res.status(403).send('Access Denied: You do not have permission to view this page.');
//     }
// });

// app.get('/admin', isAuthenticated, (req, res) => {
//     if (req.session.user.role === 'admin') {
//         res.sendFile(path.join(__dirname, 'views', 'admin.html'));
//     } else {
//         res.status(403).send('Access Denied: You must be an administrator to view this page.');
//     }
// });

// app.get('/payment', isAuthenticated, (req, res) => {
//     if (req.session.user.role === 'user' || req.session.user.role === 'admin') {
//         res.sendFile(path.join(__dirname, 'views', 'payment.html'));
//     } else {
//         res.status(403).send('Access Denied: You do not have permission to view this page.');
//     }
// });

// app.get('/diagnosis', isAuthenticated, (req, res) => {
//     if (req.session.user.role === 'technician' || req.session.user.role === 'user' || req.session.user.role === 'admin') {
//         res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
//     } else {
//         res.status(403).send('Access Denied: You do not have permission to view this page.');
//     }
// });

// // Serve static files (like CSS, JavaScript, images) from 'public'
// app.use(express.static(path.join(__dirname, 'public')));

// // Serve all HTML files directly from 'views' if no specific route matches above
// // This MUST come AFTER specific protected HTML routes to apply isAuthenticated
// app.use(express.static(path.join(__dirname, 'views')));

// // Serve the main index.html file as the homepage (this will now be caught by the static serve above)
// app.get('/', (req, res) => {
//     res.sendFile(path.join(__dirname, 'views', 'index.html'));
// });
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/');
}

// Serve static assets (CSS, JS, Images)
app.use(express.static(path.join(__dirname, 'public')));

// === PROTECTED ROUTES ===
app.get('/user', isAuthenticated, (req, res) => {
    if (['user', 'admin'].includes(req.session.user.role)) {
        res.sendFile(path.join(__dirname, 'views', 'user.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/technician', isAuthenticated, (req, res) => {
    if (['technician', 'admin'].includes(req.session.user.role)) {
        res.sendFile(path.join(__dirname, 'views', 'technician.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/admin', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'admin.html'));
    } else {
        res.status(403).send('Access Denied: You must be an administrator to view this page.');
    }
});

app.get('/payment', isAuthenticated, (req, res) => {
    if (['user', 'admin'].includes(req.session.user.role)) {
        res.sendFile(path.join(__dirname, 'views', 'payment.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/diagnosis', isAuthenticated, (req, res) => {
    if (['user', 'technician', 'admin'].includes(req.session.user.role)) {
        res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

// === HOMEPAGE ===
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// === API: Get current user ===
app.get('/api/user/me', isAuthenticated, async (req, res) => {
    try {
        const users = await readUsers();
        const currentUser = users.find(u => u.id === req.session.user.id);
        if (currentUser) {
            const { password, ...safeUser } = currentUser;
            res.json({ success: true, user: safeUser });
        } else {
            req.session.destroy(err => {
                if (err) console.error('Session destruction error on user not found:', err);
                res.status(401).json({ success: false, message: 'User session invalid. Please log in again.', redirect: '/' });
            });
        }
    } catch (err) {
        console.error('Error in /api/user/me:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching user details.' });
    }
});


// API to get current logged-in user details
app.get('/api/user/me', isAuthenticated, async (req, res) => {
    try {
        const users = await readUsers(); // Fetch users to get up-to-date user info
        const currentUser = users.find(u => u.id === req.session.user.id);
        if (currentUser) {
            // Only expose necessary user details
            const { password, ...safeUser } = currentUser;
            res.json({ success: true, user: safeUser });
        } else {
            // User not found in data file (e.g., file reset), force logout
            req.session.destroy(err => {
                if (err) console.error('Session destruction error on user not found:', err);
                res.status(401).json({ success: false, message: 'User session invalid. Please log in again.', redirect: '/' });
            });
        }
    } catch (err) {
        console.error('Error in /api/user/me:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching user details.' });
    }
});


// Send OTP
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required to send OTP.' });
        }
        const otp = generateOTP();
        otpStore[email] = { otp, expiresAt: Date.now() + 300000 }; // OTP valid for 5 minutes (300,000 ms)
        console.log(`Generated OTP for ${email}: ${otp}`); // For debugging

        const sent = await sendEmailOTP(email, otp);
        if (sent) {
            return res.json({ success: true, message: `OTP sent to ${email}. Please check your email.` });
        } else {
            return res.status(500).json({ success: false, message: 'Failed to send OTP email. Please check server logs and Nodemailer configuration.' });
        }
    } catch (err) {
        console.error('Send OTP Error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP sending.' });
    }
});

// Verify OTP
app.post('/verify-otp', (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email and OTP are required for verification.' });
        }
        const storedOtpData = otpStore[email];
        if (!storedOtpData) {
            return res.status(400).json({ success: false, message: 'No OTP found for this email or it has expired.' });
        }
        if (Date.now() > storedOtpData.expiresAt) {
            delete otpStore[email]; // Clear expired OTP
            return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
        }
        if (storedOtpData.otp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
        }
        delete otpStore[email]; // OTP successfully verified, remove it
        return res.json({ success: true, message: 'OTP verified successfully.' });
    } catch (err) {
        console.error('Verify OTP Error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP verification.' });
    }
});

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { fullName, email, phoneNumber, password, role, aadhaar, pan, bankDetails, skills } = req.body;
        let users = await readUsers(); // Read users from file

        if (!fullName || !email || !phoneNumber || !password || !role) {
            return res.status(400).json({ success: false, message: 'All required fields must be provided.' });
        }
        if (users.some(user => user.email === email)) {
            return res.status(409).json({ success: false, message: 'User with this email already exists. Please login or use a different email.' });
        }
        if (users.some(user => user.phoneNumber === phoneNumber)) {
            return res.status(409).json({ success: false, message: 'User with this phone number already exists. Please login or use a different phone number.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // HASH THE PASSWORD

        const newUser = {
            id: Date.now().toString(), // Simple unique ID
            fullName,
            email,
            phoneNumber,
            password: hashedPassword, // Store hashed password
            role,
            createdAt: new Date().toISOString(),
            verified: true, // Assumed true after OTP verification
            kycStatus: '1' // Set default KYC status
        };

        if (role === 'technician') {
            if (!aadhaar || !pan || !bankDetails || !skills) {
                return res.status(400).json({ success: false, message: 'Technician registration requires Aadhaar, PAN, Bank Details, and Skills.' });
            }
            newUser.aadhaar = aadhaar;
            newUser.pan = pan;
            newUser.bankDetails = bankDetails; // Store as received from client
            newUser.skills = skills.split(',').map(s => s.trim());
            newUser.kycStatus = 'pending'; // Initial status for technician KYC
        } else {
            newUser.kycStatus = '1'; // For users and admins
        }

        users.push(newUser); // Add to array
        await writeUsers(users); // Write updated users back to file

        console.log("Registered User:", newUser); // For debugging locally

        res.json({ success: true, message: `Registration successful for ${role}. You can now log in.` });

    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during registration.' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        console.log('Received login request body:', req.body);
        const { email, password, role } = req.body;
        let users = await readUsers(); // Read users from file for login

        if (!email || !password || !role) {
            return res.status(400).json({ success: false, message: 'Email, password, and role are required for login.' });
        }

        const user = users.find(u => u.email === email && u.role === role);

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email, password, or role mismatch.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password); // COMPARE HASHED PASSWORD
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        if (user.role === 'technician' && user.kycStatus !== 'approved') {
            if (user.kycStatus === 'pending') {
                return res.status(403).json({ success: false, message: `Your technician application is ${user.kycStatus}. Please wait for approval to access technician features.` });
            } else if (user.kycStatus === 'rejected') {
                return res.status(403).json({ success: false, message: `Your technician application has been rejected. Please contact support.` });
            }
        }

        // Set session user
        req.session.user = {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            kycStatus: user.kycStatus // Include kycStatus in session
        };

        let redirectUrl;
        switch (user.role) {
            case 'user':
                redirectUrl = '/user';
                break;
            case 'technician':
                redirectUrl = '/technician';
                break;
            case 'admin':
                redirectUrl = '/admin';
                break;
            default:
                console.warn(`Login successful for unknown role: ${user.role}. Redirecting to /`);
                redirectUrl = '/';
                break;
        }

        console.log(`User ${user.email} (${user.role}) logged in. Redirecting to ${redirectUrl}`); // For debugging

        console.log('Sending login response:', { success: true, message: 'Login successful', redirect: redirectUrl, user: req.session.user });
        return res.json({
            success: true,
            message: 'Login successful',
            redirect: redirectUrl,
            user: req.session.user // Send user data for client-side use
        });

    } catch (err) {
        console.error('Login Error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during login.' });
    }
});

// Book Service API for Users
app.post('/api/book-service', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can book services.' });
        }

        const { applianceType, location, scheduledDateTime, notes } = req.body;
        let jobs = await readJobs(); // Read jobs from file
        let users = await readUsers(); // Read users from file to find technicians

        if (!applianceType || !location || !scheduledDateTime) {
            return res.status(400).json({ success: false, message: 'Appliance type, location, and scheduled date/time are required for booking.' });
        }

        const availableTechnicians = users.filter(user => user.role === 'technician' && user.kycStatus === 'approved');
        const assignedTechnician = availableTechnicians.length > 0 ? availableTechnicians[Math.floor(Math.random() * availableTechnicians.length)] : null;

        const customerName = req.session.user.fullName;
        const customerEmail = req.session.user.email;

        const newJob = {
            id: `J${Date.now().toString().slice(-6)}`,
            userId: req.session.user.id,
            customerName: customerName,
            customerEmail: customerEmail,
            applianceType,
            location,
            scheduledDateTime,
            notes,
            status: 'Pending',
            assignedTechnicianId: assignedTechnician ? assignedTechnician.id : null,
            assignedTechnicianName: assignedTechnician ? assignedTechnician.fullName : 'Pending Assignment',
            createdAt: new Date().toISOString()
        };

        jobs.push(newJob);
        await writeJobs(jobs); // Write jobs to file

        res.json({ success: true, message: 'Booking request received successfully. A technician will be assigned soon.', jobId: newJob.id });
    } catch (err) {
        console.error('Book Service Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during service booking.' });
    }
});

// Technician Job List API
app.get('/api/technician/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can view jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot view jobs.' });
        }

        const technicianId = req.session.user.id;
        let jobs = await readJobs();

        const technicianJobs = jobs.filter(job =>
            (job.assignedTechnicianId === technicianId && job.status !== 'Completed' && job.status !== 'Cancelled') ||
            (job.status === 'Pending' && !job.assignedTechnicianId)
        );

        res.json({ success: true, jobs: technicianJobs });
    } catch (err) {
        console.error('Fetch Technician Jobs Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching technician jobs.' });
    }
});

// Technician Accept Job API
app.post('/api/technician/jobs/accept', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can accept jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot accept jobs.' });
        }

        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.status === 'Pending');

        if (jobIndex > -1) {
            if (jobs[jobIndex].assignedTechnicianId && jobs[jobIndex].assignedTechnicianId !== req.session.user.id) {
                return res.status(409).json({ success: false, message: 'This job has already been assigned to another technician.' });
            }

            jobs[jobIndex].assignedTechnicianId = req.session.user.id;
            jobs[jobIndex].assignedTechnicianName = req.session.user.fullName;
            jobs[jobIndex].status = 'Accepted';
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            await writeJobs(jobs);
            res.json({ success: true, message: 'Job accepted successfully!', job: jobs[jobIndex] });
        } else {
            res.status(404).json({ success: false, message: 'Job not found or not in pending status.' });
        }
    } catch (err) {
        console.error('Accept Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job acceptance.' });
    }
});

// Technician Start Job API
app.post('/api/technician/jobs/start', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can start jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot start jobs.' });
        }

        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.assignedTechnicianId === req.session.user.id && j.status === 'Accepted');

        if (jobIndex > -1) {
            jobs[jobIndex].status = 'In Progress';
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            await writeJobs(jobs);
            res.json({ success: true, message: 'Job status updated to In Progress!', job: jobs[jobIndex] });
        } else {
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in Accepted status.' });
        }
    } catch (err) {
        console.error('Start Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job start.' });
    }
});

// Technician Complete Job API
app.post('/api/technician/jobs/complete', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can complete jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot complete jobs.' });
        }

        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.assignedTechnicianId === req.session.user.id && (j.status === 'In Progress' || j.status === 'Diagnosed'));

        if (jobIndex > -1) {
            jobs[jobIndex].status = 'Completed';
            jobs[jobIndex].completedAt = new Date().toISOString();
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            await writeJobs(jobs);
            res.json({ success: true, message: 'Job marked as Completed!', job: jobs[jobIndex] });
        } else {
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in correct status for completion.' });
        }
    } catch (err) {
        console.error('Complete Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job completion.' });
    }
});

// Get Single Job Details API (for all roles if authorized)
app.get('/api/jobs/:jobId', isAuthenticated, async (req, res) => {
    try {
        const jobId = req.params.jobId;
        let jobs = await readJobs();
        const job = jobs.find(j => j.id === jobId);

        if (job) {
            if (req.session.user.role === 'admin' || job.userId === req.session.user.id || job.assignedTechnicianId === req.session.user.id) {
                let users = await readUsers(); // Read users from file
                const customer = users.find(u => u.id === job.userId);
                const technician = users.find(u => u.id === job.assignedTechnicianId);

                const jobDetails = {
                    ...job,
                    customerName: customer ? customer.fullName : 'N/A',
                    customerPhoneNumber: customer ? customer.phoneNumber : 'N/A',
                    technicianName: technician ? technician.fullName : 'N/A',
                    technicianPhoneNumber: technician ? technician.phoneNumber : 'N/A'
                };
                res.json({ success: true, job: jobDetails });
            } else {
                res.status(403).json({ success: false, message: 'Access denied to this job.' });
            }
        } else {
            res.status(404).json({ success: false, message: 'Job not found.' });
        }
    } catch (err) {
        console.error('Get Job Details Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching job details.' });
    }
});

// Technician Diagnosis and Quotation API
app.post('/api/technician/diagnosis', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can submit diagnosis.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot submit diagnosis.' });
        }

        const { jobId, faultyParts, technicianRemarks, partCost, laborCost, travelCharges, totalEstimate } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.assignedTechnicianId === req.session.user.id && (j.status === 'In Progress' || j.status === 'Accepted'));

        if (jobIndex > -1) {
            jobs[jobIndex].faultyParts = faultyParts;
            jobs[jobIndex].technicianRemarks = technicianRemarks;
            jobs[jobIndex].quotation = {
                partCost: parseFloat(partCost),
                laborCost: parseFloat(laborCost),
                travelCharges: parseFloat(travelCharges),
                totalEstimate: parseFloat(totalEstimate),
                createdAt: new Date().toISOString()
            };
            jobs[jobIndex].status = 'Diagnosed';
            jobs[jobIndex].lastUpdated = new Date().toISOString();

            await writeJobs(jobs);
            res.json({ success: true, message: 'Diagnosis & Quotation saved successfully.', job: jobs[jobIndex] });
        } else {
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in correct status for diagnosis.' });
        }
    } catch (err) {
        console.error('Technician Diagnosis Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during diagnosis submission.' });
    }
});

// User Job List API
app.get('/api/user/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can view their jobs.' });
        }
        const userId = req.session.user.id;
        let jobs = await readJobs();
        const userJobs = jobs.filter(job => job.userId === userId);

        res.json({ success: true, jobs: userJobs });
    } catch (err) {
        console.error('Fetch User Jobs Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching user jobs.' });
    }
});

// User Cancel Job API
app.post('/api/user/jobs/cancel', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can cancel jobs.' });
        }
        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.userId === req.session.user.id);

        if (jobIndex > -1) {
            if (jobs[jobIndex].status === 'Pending' || jobs[jobIndex].status === 'Accepted') {
                jobs[jobIndex].status = 'Cancelled';
                jobs[jobIndex].lastUpdated = new Date().toISOString();
                await writeJobs(jobs);
                res.json({ success: true, message: 'Job cancelled successfully!' });
            } else {
                res.status(400).json({ success: false, message: `Job cannot be cancelled at its current status (${jobs[jobIndex].status}).` });
            }
        } else {
            res.status(404).json({ success: false, message: 'Job not found or not associated with your account.' });
        }
    }
    catch (err) {
        console.error('Cancel Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job cancellation.' });
    }
});

// Process Payment API
app.post('/api/process-payment', isAuthenticated, async (req, res) => {
    try {
        const { jobId, totalAmount, paymentMethod, paymentDetails } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId);

        if (jobIndex > -1) {
            // Ensure only the job owner or an admin can process payment for this job
            if (jobs[jobIndex].userId !== req.session.user.id && req.session.user.role !== 'admin') {
                return res.status(403).json({ success: false, message: 'Access denied to process payment for this job.' });
            }

            // Check if the job is in a state where payment can be processed
            if (jobs[jobIndex].status !== 'Diagnosed' && jobs[jobIndex].status !== 'Completed') {
                return res.status(400).json({ success: false, message: `Payment can only be processed for jobs that are 'Diagnosed' or 'Completed'. Current status: ${jobs[jobIndex].status}.` });
            }

            // Basic validation for payment details
            if (!totalAmount || !paymentMethod) {
                return res.status(400).json({ success: false, message: 'Total amount and payment method are required.' });
            }

            // Simulate payment processing (in a real app, integrate with a payment gateway)
            console.log(`Processing payment for Job ID: ${jobId}, Amount: ${totalAmount}, Method: ${paymentMethod}`);
            // Add more sophisticated payment processing logic here (e.g., calling a third-party API)

            jobs[jobIndex].payment = {
                amount: parseFloat(totalAmount),
                method: paymentMethod,
                details: paymentDetails, // e.g., transaction ID, last 4 digits of card
                status: 'Paid',
                paidAt: new Date().toISOString()
            };
            jobs[jobIndex].status = 'Paid'; // Update job status to Paid after successful payment
            jobs[jobIndex].lastUpdated = new Date().toISOString();

            await writeJobs(jobs); // Save updated job data

            res.json({ success: true, message: 'Payment processed successfully and job marked as Paid!', job: jobs[jobIndex] });

        } else {
            res.status(404).json({ success: false, message: 'Job not found.' });
        }
    } catch (err) {
        console.error('Process Payment Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during payment processing.' });
    }
});


// Admin API: Get All Users
app.get('/api/admin/users', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only administrators can view users.' });
        }
        const users = await readUsers();
        // Filter out sensitive information like passwords before sending
        const safeUsers = users.map(user => {
            const { password, ...rest } = user;
            return rest;
        });
        res.json({ success: true, users: safeUsers });
    } catch (err) {
        console.error('Admin Get Users Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching users.' });
    }
});

// Admin Dashboard Overview API
app.get('/api/admin/dashboard-overview', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can view dashboard overview.' });
        }

        const currentUsers = await readUsers(); // Read users from file
        const currentJobs = await readJobs();   // Fetch latest jobs from file

        const totalJobs = currentJobs.length;
        const activeTechnicians = currentUsers.filter(u => u.role === 'technician' && u.kycStatus === 'approved').length;

        const now = new Date();
        const currentMonth = now.getMonth();
        const currentYear = now.getFullYear();

        const revenueThisMonth = currentJobs.reduce((sum, job) => {
            if (job.payment && job.payment.status === 'Paid' && job.payment.paidAt) {
                const paidDate = new Date(job.payment.paidAt);
                if (paidDate.getMonth() === currentMonth && paidDate.getFullYear() === currentYear) {
                    return sum + (job.payment.amount || 0); // Use payment.amount for revenue calculation
                }
            }
            return sum;
        }, 0);

        const pendingApprovals = currentUsers.filter(u => u.role === 'technician' && u.kycStatus === 'pending').length;

        res.json({
            success: true,
            data: {
                totalJobs,
                activeTechnicians,
                revenueThisMonth: parseFloat(revenueThisMonth.toFixed(2)),
                pendingApprovals
            }
        });

    } catch (err) {
        console.error('Admin Dashboard Overview Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching dashboard overview.' });
    }
});

// Admin API: Get All Jobs (Enhanced)
app.get('/api/admin/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only administrators can view all jobs.' });
        }
        let jobs = await readJobs(); // Read jobs from file
        let users = await readUsers(); // Read users from file to enhance job data

        const enhancedJobs = jobs.map(job => {
            const customer = users.find(u => u.id === job.userId);
            const technician = users.find(u => u.id === job.assignedTechnicianId);
            return {
                ...job,
                customerName: customer ? customer.fullName : 'N/A',
                customerEmail: customer ? customer.email : 'N/A',
                customerPhoneNumber: customer ? customer.phoneNumber : 'N/A',
                technicianName: technician ? technician.fullName : 'Pending Assignment',
                technicianEmail: technician ? technician.email : 'N/A',
                technicianPhoneNumber: technician ? technician.phoneNumber : 'N/A'
            };
        });

        res.json({ success: true, jobs: enhancedJobs });
    } catch (err) {
        console.error('Admin Fetch All Jobs Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching all jobs.' });
    }
});

// Admin API: Assign/Reassign Technician to a Job
app.post('/api/admin/jobs/assign-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only administrators can assign technicians.' });
        }
        const { jobId, technicianId } = req.body;
        let jobs = await readJobs();
        let users = await readUsers();

        const jobIndex = jobs.findIndex(j => j.id === jobId);
        if (jobIndex === -1) {
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const technician = users.find(u => u.id === technicianId && u.role === 'technician' && u.kycStatus === 'approved');
        if (!technician) {
            return res.status(404).json({ success: false, message: 'Technician not found or not approved.' });
        }

        jobs[jobIndex].assignedTechnicianId = technician.id;
        jobs[jobIndex].assignedTechnicianName = technician.fullName;
        jobs[jobIndex].lastUpdated = new Date().toISOString();

        // If the job was pending, change its status to 'Accepted' upon manual assignment
        if (jobs[jobIndex].status === 'Pending') {
            jobs[jobIndex].status = 'Accepted';
        }

        await writeJobs(jobs);
        res.json({ success: true, message: `Technician ${technician.fullName} assigned to job ${jobId}.`, job: jobs[jobIndex] });

    } catch (err) {
        console.error('Admin Assign Technician Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while assigning technician.' });
    }
});


// Admin Grant Technician KYC Approval
app.post('/api/admin/users/:userId/grant-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can modify user roles.' });
        }

        const userId = req.params.userId;
        let users = await readUsers(); // Read users from file
        const userIndex = users.findIndex(u => u.id === userId && u.role === 'technician');

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'Technician not found or not a technician role.' });
        }

        if (users[userIndex].kycStatus === 'approved') {
            return res.status(400).json({ success: false, message: 'Technician is already approved.' });
        }

        users[userIndex].kycStatus = 'approved';
        users[userIndex].lastUpdated = new Date().toISOString();

        await writeUsers(users); // Write updated users back to file
        res.json({ success: true, message: 'Technician KYC approved successfully.', user: users[userIndex] });
    } catch (err) {
        console.error('Admin Grant Technician Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while granting technician role.' });
    }
});

// Admin Reject Technician KYC
app.post('/api/admin/users/:userId/reject-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can reject technician KYC.' });
        }

        const userId = req.params.userId;
        let users = await readUsers(); // Read users from file
        const userIndex = users.findIndex(u => u.id === userId && u.role === 'technician');

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'Technician not found or not a technician role.' });
        }

        if (users[userIndex].kycStatus === 'rejected') {
            return res.status(400).json({ success: false, message: 'Technician KYC is already rejected.' });
        }

        users[userIndex].kycStatus = 'rejected';
        users[userIndex].lastUpdated = new Date().toISOString();

        await writeUsers(users); // Write updated users back to file
        res.json({ success: true, message: 'Technician KYC rejected successfully.', user: users[userIndex] });
    } catch (err) {
        console.error('Admin Reject Technician KYC Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while rejecting technician KYC.' });
    }
});


// Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Could not log out. Please try again.' });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ success: true, message: 'Logged out successfully.', redirect: '/' });
    });
});


// Handle 404 - Keep this at the very end
app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, 'views', '404.html')); // Make sure you have a 404.html in your views folder
});


// Start the server
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log('⚠️ IMPORTANT: User and Job data is stored in JSON files but will reset on server restart on Render (ephemeral filesystem)!');
    console.log('For persistent data on Render, you MUST use a real database (e.g., MongoDB Atlas, PostgreSQL).');
    console.log('Remember to set EMAIL_USER, EMAIL_PASS, and SESSION_SECRET in your Render environment variables!');
});
