const express = require('express');
const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs'); // Add bcryptjs for password hashing
require('dotenv').config(); // Load environment variables from .env file

const app = express();

// === Create data directory if it doesn't exist ===
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log('Created data directory.');
}

// === File paths for JSON data storage ===
const USERS_JSON = path.join(dataDir, 'users.json');
const JOBS_JSON = path.join(dataDir, 'jobs.json');

// Ensure JSON files exist with empty arrays if not present.
async function initializeDataFiles() {
    try {
        await fsp.access(USERS_JSON);
    } catch (e) {
        await fsp.writeFile(USERS_JSON, '[]', 'utf8');
        console.log('Created empty users.json');
    }
    try {
        await fsp.access(JOBS_JSON);
    } catch (e) {
        await fsp.writeFile(JOBS_JSON, '[]', 'utf8');
        console.log('Created empty jobs.json');
    }
}
initializeDataFiles();

// === Middleware Setup ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session management middleware setup.
app.use(session({
    secret: process.env.SESSION_SECRET || 'a_very_long_and_random_secret_for_session_management_replace_this_in_production', // ⚠️ IMPORTANT: Use environment variable
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
        pass: process.env.EMAIL_PASS  // ⚠️ IMPORTANT: Get from environment variable (App password for Gmail)
    }
});

// === In-memory OTP Store ===
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
            return []; // File does not exist, return empty array
        }
        console.error('Error reading users.json:', error);
        return []; // Return empty array on other errors
    }
}

async function writeUsers(users) {
    try {
        await fsp.writeFile(USERS_JSON, JSON.stringify(users, null, 2), 'utf8');
    } catch (error) {
        console.error('Error writing users.json:', error);
    }
}

async function readJobs() {
    try {
        const data = await fsp.readFile(JOBS_JSON, 'utf8');
        return data.trim() ? JSON.parse(data) : [];
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }
        console.error('Error reading jobs.json:', error);
        return [];
    }
}

async function writeJobs(jobs) {
    try {
        await fsp.writeFile(JOBS_JSON, JSON.stringify(jobs, null, 2), 'utf8');
    } catch (error) {
        console.error('Error writing jobs.json:', error);
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
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.id) {
        next();
    } else {
        // If not authenticated, send a JSON response to allow client-side redirect
        res.status(401).json({ success: false, message: 'Unauthorized. Please login.', redirect: '/' });
    }
}

// === Routes ===

// Serve specific HTML files WITH authentication and role checks FIRST
// Order matters: specific protected routes before general static serving
app.get('/user.html', isAuthenticated, (req, res) => {
    // Check if user is trying to access their own dashboard or is an admin
    if (req.session.user.role === 'user' || req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'user.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/technician.html', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'technician' || req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'technician.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/admin.html', isAuthenticated, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'admin.html'));
    } else {
        res.status(403).send('Access Denied: You must be an administrator to view this page.');
    }
});

app.get('/payment.html', isAuthenticated, (req, res) => {
    // Payment page accessible by users and admins who are associated with the job
    // (A more robust check might be needed here, e.g., if job belongs to current user)
    if (req.session.user.role === 'user' || req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'payment.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

app.get('/diagnosis.html', isAuthenticated, (req, res) => {
    // Diagnosis page could be for technicians or users viewing their diagnosis
    if (req.session.user.role === 'technician' || req.session.user.role === 'user' || req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
    } else {
        res.status(403).send('Access Denied: You do not have permission to view this page.');
    }
});

// Serve static files (like CSS, JavaScript, images) from 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Serve all HTML files directly from 'views' if no specific route matches above
// This MUST come AFTER specific protected HTML routes to apply isAuthenticated
app.use(express.static(path.join(__dirname, 'views')));

// Serve the main index.html file as the homepage (this will now be caught by the static serve above)
// If you want index.html to be served ONLY from views:
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});


// API to get current logged-in user details
app.get('/api/user/me', isAuthenticated, (req, res) => {
    // Only return safe user data from session
    const user = { ...req.session.user };
    res.json({ success: true, user: user });
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
        let users = await readUsers();

        if (!fullName || !email || !phoneNumber || !password || !role) {
            return res.status(400).json({ success: false, message: 'All required fields must be provided.' });
        }
        if (users.some(user => user.email === email)) {
            return res.status(409).json({ success: false, message: 'User with this email already exists. Please login or use a different email.' });
        }
        if (users.some(user => user.phoneNumber === phoneNumber)) {
            return res.status(409).json({ success: false, message: 'User with this phone number already exists. Please login or use a different phone number.' });
        }

        // HASH THE PASSWORD BEFORE STORING
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        const newUser = {
            id: Date.now().toString(), // Simple unique ID
            fullName,
            email,
            phoneNumber,
            password: hashedPassword, // Store hashed password
            role,
            createdAt: new Date().toISOString(),
            verified: true // Assumed true after OTP verification
        };

        if (role === 'technician') {
            // Check for required technician fields
            if (!aadhaar || !pan || !bankDetails || !skills) {
                return res.status(400).json({ success: false, message: 'Technician registration requires Aadhaar, PAN, Bank Details, and Skills.' });
            }
            newUser.aadhaar = aadhaar;
            newUser.pan = pan;
            newUser.bankDetails = bankDetails;
            newUser.skills = skills.split(',').map(s => s.trim());
            newUser.kycStatus = 'pending'; // Initial status for technician KYC
        } else {
            newUser.kycStatus = 'N/A'; // For users and admins
        }

        users.push(newUser);
        await writeUsers(users);

        res.json({ success: true, message: `Registration successful for ${role}. You can now log in.` });

    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during registration.' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        let users = await readUsers();

        if (!email || !password || !role) {
            return res.status(400).json({ success: false, message: 'Email, password, and role are required for login.' });
        }

        const user = users.find(u => u.email === email && u.role === role);

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email, password, or role mismatch.' });
        }

        // COMPARE HASHED PASSWORD
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Technician KYC status check (allow login if 'approved' or 'N/A' for non-technicians, or for newly registered technicians with 'pending' status)
        // Adjusting this logic: Technicians with 'pending' KYC should NOT be able to access the technician dashboard yet.
        if (user.role === 'technician' && user.kycStatus !== 'approved') {
            // Also allow 'pending' for first-time login after registration, but block if explicitly rejected
            if (user.kycStatus === 'pending') {
                // Allow login but redirect to a specific 'status' page or show a message.
                // For now, let's just show a message.
                // If you want them to be redirected to a "KYC Pending" page, define it.
                return res.status(403).json({ success: false, message: `Your technician application is ${user.kycStatus}. Please wait for approval to access technician features.` });
            } else if (user.kycStatus === 'rejected') {
                return res.status(403).json({ success: false, message: `Your technician application has been rejected. Please contact support.` });
            }
            // For other unexpected kycStatus, you might also want to block.
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
                redirectUrl = '/user.html';
                break;
            case 'technician':
                redirectUrl = '/technician.html';
                break;
            case 'admin':
                redirectUrl = '/admin.html';
                break;
            default:
                // This case should ideally not be reached if roles are controlled at signup
                return res.status(400).json({ success: false, message: 'Unknown user role. Please contact support.' });
        }

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
        let jobs = await readJobs();
        let users = await readUsers();

        if (!applianceType || !location || !scheduledDateTime) {
            return res.status(400).json({ success: false, message: 'Appliance type, location, and scheduled date/time are required for booking.' });
        }

        // Only assign to approved technicians
        const availableTechnicians = users.filter(user => user.role === 'technician' && user.kycStatus === 'approved');
        // Simple round-robin or random assignment; improve for real-world (e.g., location, skills match)
        const assignedTechnician = availableTechnicians.length > 0 ? availableTechnicians[Math.floor(Math.random() * availableTechnicians.length)] : null;

        const customerName = req.session.user.fullName; // Get from session
        const customerEmail = req.session.user.email; // Get from session

        const newJob = {
            id: `J${Date.now().toString().slice(-6)}`, // Simple unique job ID
            userId: req.session.user.id,
            customerName: customerName,
            customerEmail: customerEmail, // Store customer email
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
        await writeJobs(jobs);

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
        // Ensure technician's KYC is approved to view jobs
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot view jobs.' });
        }

        const technicianId = req.session.user.id;
        let jobs = await readJobs();
        
        // Filter jobs that are either assigned to this technician (and not completed/cancelled)
        // OR jobs that are 'Pending' and not yet assigned to anyone, which the technician might accept
        const technicianJobs = jobs.filter(job =>
            (job.assignedTechnicianId === technicianId && job.status !== 'Completed' && job.status !== 'Cancelled') ||
            (job.status === 'Pending' && !job.assignedTechnicianId) // Unassigned jobs
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
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.status === 'Pending'); // Only allow accepting pending jobs

        if (jobIndex > -1) {
            // Ensure job is not already assigned to someone else
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
        // Technician can only start jobs assigned to them and in 'Accepted' status
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
        // Technician can only complete jobs assigned to them and in 'In Progress' or 'Diagnosed' status
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
            // Authorization: Admin, Job's User, or Assigned Technician can view
            if (req.session.user.role === 'admin' || job.userId === req.session.user.id || job.assignedTechnicianId === req.session.user.id) {
                const users = await readUsers();
                const customer = users.find(u => u.id === job.userId);
                const technician = users.find(u => u.id === job.assignedTechnicianId);

                const jobDetails = {
                    ...job,
                    customerName: customer ? customer.fullName : 'N/A',
                    customerPhoneNumber: customer ? customer.phoneNumber : 'N/A', // Add customer phone
                    technicianName: technician ? technician.fullName : 'N/A',
                    technicianPhoneNumber: technician ? technician.phoneNumber : 'N/A' // Add technician phone
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
        // Technician can only diagnose jobs assigned to them and in 'In Progress' or 'Accepted' status
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
            jobs[jobIndex].status = 'Diagnosed'; // Update status to Diagnosed
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
            // Allow cancellation only if job is Pending or Accepted, not if already In Progress/Diagnosed/Completed
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

// Process Payment API (could be called by user after seeing quotation, or admin)
app.post('/api/process-payment', isAuthenticated, async (req, res) => {
    try {
        // This payment route is flexible, assuming it can be triggered by user or admin
        const { jobId, totalAmount, paymentMethod, paymentDetails } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId);

        if (jobIndex > -1) {
            // Basic authorization: user must own job, or current user is admin
            if (jobs[jobIndex].userId !== req.session.user.id && req.session.user.role !== 'admin') {
                return res.status(403).json({ success: false, message: 'Access denied to process payment for this job.' });
            }

            if (jobs[jobIndex].status !== 'Diagnosed' && jobs[jobIndex].status !== 'Completed') {
                return res.status(400).json({ success: false, message: 'Payment can only be processed for diagnosed or already completed jobs.' });
            }
            if (jobs[jobIndex].paymentStatus === 'Paid') {
                return res.status(400).json({ success: false, message: 'This job has already been paid for.' });
            }

            jobs[jobIndex].paymentStatus = 'Paid';
            jobs[jobIndex].paymentDetails = { method: paymentMethod, ...paymentDetails, amount: totalAmount }; // Store amount paid
            jobs[jobIndex].status = 'Completed'; // Mark job as completed upon payment
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            jobs[jobIndex].paidAt = new Date().toISOString(); // Timestamp payment

            await writeJobs(jobs);
            res.json({ success: true, message: 'Payment processed successfully. Job marked as completed.' });
        } else {
            res.status(404).json({ success: false, message: 'Job not found for payment processing.' });
        }
    } catch (err) {
        console.error('Process Payment Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during payment processing.' });
    }
});

// User Submit Review API
app.post('/api/user/submit-review', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can submit reviews.' });
        }

        const { jobId, rating, reviewText } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.userId === req.session.user.id);

        if (jobIndex > -1) {
            if (jobs[jobIndex].status !== 'Completed') {
                return res.status(400).json({ success: false, message: 'Only completed jobs can be reviewed.' });
            }
            // Ensure a job can only be reviewed once
            if (jobs[jobIndex].rating || jobs[jobIndex].reviewText) {
                return res.status(400).json({ success: false, message: 'This job has already been reviewed.' });
            }

            jobs[jobIndex].rating = rating;
            jobs[jobIndex].reviewText = reviewText;
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            await writeJobs(jobs);
            res.json({ success: true, message: 'Review submitted successfully!' });
        } else {
            res.status(404).json({ success: false, message: 'Job not found or not associated with your account.' });
        }
    } catch (err) {
        console.error('Submit Review Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during review submission.' });
    }
});


// === ADMIN SPECIFIC APIs ===

// Admin Get All Users API
app.get('/api/admin/users', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can view users.' });
        }
        let users = await readUsers();
        // Remove password hash before sending to client for security
        const safeUsers = users.map(user => {
            const { password, ...rest } = user; // Destructure to exclude password
            return rest;
        });
        res.json({ success: true, users: safeUsers });
    } catch (err) {
        console.error('Admin Fetch Users Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching users.' });
    }
});

// Admin Get All Jobs API
app.get('/api/admin/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can view all jobs.' });
        }
        let jobs = await readJobs();
        let users = await readUsers();

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

// Admin Grant Technician KYC Approval
app.post('/api/admin/users/:userId/grant-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can modify user roles.' });
        }

        const userId = req.params.userId;
        let users = await readUsers();
        // Find technician by ID and ensure they are indeed a technician
        const userIndex = users.findIndex(u => u.id === userId && u.role === 'technician');

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'Technician not found or not a technician role.' });
        }

        if (users[userIndex].kycStatus === 'approved') {
            return res.status(400).json({ success: false, message: 'Technician is already approved.' });
        }

        users[userIndex].kycStatus = 'approved';
        users[userIndex].lastUpdated = new Date().toISOString();

        await writeUsers(users);
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
        let users = await readUsers();
        const userIndex = users.findIndex(u => u.id === userId && u.role === 'technician');

        if (userIndex === -1) {
            return res.status(404).json({ success: false, message: 'Technician not found or not a technician role.' });
        }

        if (users[userIndex].kycStatus === 'rejected') {
            return res.status(400).json({ success: false, message: 'Technician KYC is already rejected.' });
        }

        users[userIndex].kycStatus = 'rejected';
        users[userIndex].lastUpdated = new Date().toISOString();

        await writeUsers(users);
        res.json({ success: true, message: 'Technician KYC rejected successfully.', user: users[userIndex] });
    } catch (err) {
        console.error('Admin Reject Technician KYC Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while rejecting technician KYC.' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).json({ success: false, message: 'Could not log out.' });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ success: true, message: 'Logged out successfully.' });
    });
});

// Handle 404 - Keep this at the very end
app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, 'views', '404.html')); // Or send a simple message
});


// === Start the Server ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log('Remember to set EMAIL_USER, EMAIL_PASS, and SESSION_SECRET in your Render environment variables!');
});
