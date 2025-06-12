const express = require('express');
const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');

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
    secret: 'your_super_secret_key_for_session', // ⚠️ IMPORTANT: Change this to a long, random, and unguessable string in production!
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// === Email Transporter Setup for Nodemailer ===
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'achhutanandjha1@gmail.com', // ⚠️ IMPORTANT: Replace with your actual Gmail email address.
        pass: ''    // ⚠️ IMPORTANT: Replace with an app-specific password.
    }
});

// === In-memory OTP Store ===
const otpStore = {};

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
            return [];
        }
        console.error('Error reading users.json:', error);
        return [];
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
    try {
        await transporter.sendMail({
            from: transporter.options.auth.user,
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
        res.redirect('/');
    }
}

// === Routes ===

// Serve specific HTML files WITH authentication and role checks first
app.get('/user.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

app.get('/technician.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'technician.html'));
});

app.get('/admin.html', isAuthenticated, (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'views', 'admin.html'));
    } else {
        res.status(403).send('Access Denied: You must be an administrator to view this page.');
    }
});

app.get('/payment.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'payment.html'));
});

app.get('/diagnosis.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
});

// Serve static files (like CSS, JavaScript, images) and other HTML files without specific protection
// This must come AFTER specific protected HTML routes.
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'views'))); // Now serves 'index.html' and other public assets


// Serve the main index.html file as the homepage (this will now be caught by the static serve above)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});


app.get('/api/user/me', isAuthenticated, (req, res) => {
    const user = { ...req.session.user };
    res.json({ success: true, user: user });
});

app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required to send OTP.' });
        }
        const otp = generateOTP();
        otpStore[email] = { otp, expiresAt: Date.now() + 300000 };
        console.log(`Generated OTP for ${email}: ${otp}`);
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
            delete otpStore[email];
            return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
        }
        if (storedOtpData.otp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
        }
        delete otpStore[email];
        return res.json({ success: true, message: 'OTP verified successfully.' });
    } catch (err) {
        console.error('Verify OTP Error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP verification.' });
    }
});

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

        const newUser = {
            id: Date.now().toString(),
            fullName,
            email,
            phoneNumber,
            password, // ⚠️ IMPORTANT: In production, ALWAYS HASH PASSWORDS!
            role,
            createdAt: new Date().toISOString(),
            verified: true
        };

        if (role === 'technician') {
            if (!aadhaar || !pan || !bankDetails || !skills) {
                return res.status(400).json({ success: false, message: 'Technician registration requires Aadhaar, PAN, Bank Details, and Skills.' });
            }
            newUser.aadhaar = aadhaar;
            newUser.pan = pan;
            newUser.bankDetails = bankDetails;
            newUser.skills = skills.split(',').map(s => s.trim());
            newUser.kycStatus = 'pending'; // New field for technician KYC
        } else {
            newUser.kycStatus = 'N/A'; // For users and admins, KYC is not applicable this way
        }

        users.push(newUser);
        await writeUsers(users);

        res.json({ success: true, message: `Registration successful for ${role}. You can now log in.` });

    } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during registration.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        let users = await readUsers();

        if (!email || !password || !role) {
            return res.status(400).json({ success: false, message: 'Email, password, and role are required for login.' });
        }

        const user = users.find(u => u.email === email && u.password === password && u.role === role);

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email, password, or role mismatch.' });
        }

        if (user.role === 'technician' && user.kycStatus !== 'approved' && user.kycStatus !== 'N/A') { // Allow 'N/A' for technicians not yet having kycStatus (backward compatibility)
             return res.status(403).json({ success: false, message: `Your technician application is ${user.kycStatus}. Please wait for approval.` });
        }

        req.session.user = {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            kycStatus: user.kycStatus
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
                return res.status(400).json({ success: false, message: 'Unknown user role specified.' });
        }

        return res.json({
            success: true,
            message: 'Login successful',
            redirect: redirectUrl,
            user: req.session.user
        });

    } catch (err) {
        console.error('Login Error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during login.' });
    }
});

app.post('/api/book-service', isAuthenticated, async (req, res) => {
    try {
        const { applianceType, location, scheduledDateTime, notes } = req.body;
        let jobs = await readJobs();
        let users = await readUsers();

        if (!applianceType || !location || !scheduledDateTime) {
            return res.status(400).json({ success: false, message: 'Appliance type, location, and scheduled date/time are required for booking.' });
        }

        const technicians = users.filter(user => user.role === 'technician' && user.kycStatus === 'approved');
        const assignedTechnician = technicians.length > 0 ? technicians[Math.floor(Math.random() * technicians.length)] : null;

        const customerName = req.session.user ? req.session.user.fullName : 'Unknown User';

        const newJob = {
            id: `J${Date.now().toString().slice(-6)}`,
            userId: req.session.user.id,
            customerName: customerName,
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

app.get('/api/technician/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can view jobs.' });
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

app.post('/api/technician/jobs/accept', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can accept jobs.' });
        }

        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.status === 'Pending');

        if (jobIndex > -1) {
            if (!jobs[jobIndex].assignedTechnicianId) {
                jobs[jobIndex].assignedTechnicianId = req.session.user.id;
                jobs[jobIndex].assignedTechnicianName = req.session.user.fullName;
            }
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

app.post('/api/technician/jobs/start', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can start jobs.' });
        }
        const { jobId } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.assignedTechnicianId === req.session.user.id && (j.status === 'Accepted' || j.status === 'Assigned'));

        if (jobIndex > -1) {
            jobs[jobIndex].status = 'In Progress';
            jobs[jobIndex].lastUpdated = new Date().toISOString();
            await writeJobs(jobs);
            res.json({ success: true, message: 'Job status updated to In Progress!', job: jobs[jobIndex] });
        } else {
            res.status(404).json({ success: false, message: 'Job not found or not in correct status for starting.' });
        }
    } catch (err) {
        console.error('Start Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job start.' });
    }
});

app.post('/api/technician/jobs/complete', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can complete jobs.' });
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
            res.status(404).json({ success: false, message: 'Job not found or not in correct status for completion.' });
        }
    } catch (err) {
        console.error('Complete Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job completion.' });
    }
});


app.get('/api/jobs/:jobId', isAuthenticated, async (req, res) => {
    try {
        const jobId = req.params.jobId;
        let jobs = await readJobs();
        const job = jobs.find(j => j.id === jobId);

        if (job) {
            if (req.session.user.role === 'admin' || job.userId === req.session.user.id || job.assignedTechnicianId === req.session.user.id) {
                const users = await readUsers();
                const customer = users.find(u => u.id === job.userId);
                const technician = users.find(u => u.id === job.assignedTechnicianId);

                const jobDetails = {
                    ...job,
                    customerName: customer ? customer.fullName : 'N/A',
                    technicianName: technician ? technician.fullName : 'N/A'
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


app.post('/api/technician/diagnosis', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can submit diagnosis.' });
        }

        const { jobId, faultyParts, technicianRemarks, partCost, laborCost, travelCharges, totalEstimate } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId && j.assignedTechnicianId === req.session.user.id);

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
            res.status(404).json({ success: false, message: 'Job not found or not assigned to you.' });
        }
    } catch (err) {
        console.error('Technician Diagnosis Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during diagnosis submission.' });
    }
});

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
                res.status(400).json({ success: false, message: 'Job cannot be cancelled at its current status.' });
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

app.post('/api/process-payment', isAuthenticated, async (req, res) => {
    try {
        const { jobId, totalAmount, paymentMethod, paymentDetails } = req.body;
        let jobs = await readJobs();
        const jobIndex = jobs.findIndex(j => j.id === jobId);

        if (jobIndex > -1) {
            jobs[jobIndex].paymentStatus = 'Paid';
            jobs[jobIndex].paymentDetails = { method: paymentMethod, ...paymentDetails };
            jobs[jobIndex].status = 'Completed';
            jobs[jobIndex].lastUpdated = new Date().toISOString();
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

app.get('/api/admin/users', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can view users.' });
        }
        let users = await readUsers();
        const safeUsers = users.map(user => {
            const { password, ...rest } = user;
            return rest;
        });
        res.json({ success: true, users: safeUsers });
    } catch (err) {
        console.error('Admin Fetch Users Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching users.' });
    }
});

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
                technicianName: technician ? technician.fullName : 'Pending Assignment'
            };
        });

        res.json({ success: true, jobs: enhancedJobs });
    } catch (err) {
        console.error('Admin Fetch All Jobs Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching all jobs.' });
    }
});


app.post('/api/admin/users/:userId/grant-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can modify user roles.' });
        }

        const userId = req.params.userId;
        let users = await readUsers();
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
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logged out successfully.' });
    });
});

// === Start the Server ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});
