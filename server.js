// server.js

// Load environment variables from .env file
require('dotenv').config();

// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser'); // Deprecated but still used for body-parser specific features if needed
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo'); // For storing sessions in MongoDB
const nodemailer = require('nodemailer'); // For sending emails (e.g., OTP)
const bcrypt = require('bcryptjs'); // For password hashing
const crypto = require('crypto'); // For generating random OTPs
const path = require('path'); // Node.js path module for serving static files
const multer = require('multer'); // For handling multipart/form-data, primarily file uploads
const cors = require('cors'); // For enabling Cross-Origin Resource Sharing

// Initialize Express app
const app = express();

// Port configuration
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI; // MongoDB Atlas connection string
const SESSION_SECRET = process.env.SESSION_SECRET || 'supersecretkeyforprod'; // Use a strong, random key in production
const EMAIL_USER = process.env.EMAIL_USER; // Your Gmail email address for sending OTPs
const EMAIL_PASS = process.env.EMAIL_PASS; // Your Gmail App Password for sending OTPs

// --- MongoDB Connection ---
// Check if MONGODB_URI is provided
if (!MONGODB_URI) {
    console.error('CRITICAL ERROR: MONGODB_URI environment variable not set!');
    console.error('Please set MONGODB_URI in your Render environment variables or .env file.');
    process.exit(1); // Exit if no MongoDB URI is provided
}

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000, // Timeout for initial server discovery
    socketTimeoutMS: 45000, // Timeout for socket operations
})
.then(() => {
    console.log('✅ MongoDB Connected successfully!');
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    // Exit process if MongoDB connection fails to prevent app from running without DB
    process.exit(1);
});

// --- Mongoose Schemas and Models ---

// User Schema: Defines the structure for user documents in MongoDB
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phoneNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Hashed password
    role: { type: String, required: true, enum: ['user', 'technician', 'admin'] },
    isVerified: { type: Boolean, default: false }, // For email verification during signup
    aadhaar: { type: String, unique: true, sparse: true }, // Only for technicians; unique if exists, sparse allows nulls
    pan: { type: String, unique: true, sparse: true },     // Only for technicians; unique if exists, sparse allows nulls
    // Define bankDetails as a nested object
    bankDetails: {
        bankName: { type: String },
        accountNumber: { type: String },
        ifscCode: { type: String },
        upiId: { type: String } // New field for UPI ID
    },                                   // Only for technicians
    skills: [String],                                      // Only for technicians (array of strings)
    kycStatus: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] }, // KYC status for technicians
    // New fields for technicians' average rating and availability
    averageRating: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }, // To help calculate average rating
    balance: { type: Number, default: 0 }, // New: Technician's withdrawable balance
    availability: {
        availableDays: [String], // e.g., ['Monday', 'Wednesday']
        startTime: String,       // e.g., '09:00'
        endTime: String,         // e.g., '18:00'
        emergencyCalls: { type: Boolean, default: false }
    },
    workingLocation: {
        address: String,
        radiusKm: Number,
        latitude: Number, // Optional, for future use with real geo-data
        longitude: Number  // Optional, for future use with real geo-data
    }
}, { timestamps: true }); // Automatically add createdAt and updatedAt fields

// Pre-save hook to hash password before saving to the database
userSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    // Set kycStatus to 'pending' for new technicians by default if not already set
    if (this.isNew && this.role === 'technician' && !this.kycStatus) {
        this.kycStatus = 'pending';
    }
    next();
});

// Method to compare candidate password with the hashed password in the database
userSchema.methods.comparePassword = function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Create the User model from the schema
const User = mongoose.model('User', userSchema);

// Job Schema: Defines the structure for job requests
const jobSchema = new mongoose.Schema({
    jobId: { type: String, unique: true, required: true }, // Custom job ID (e.g., J123456)
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Reference to the customer User
    customerName: String,
    customerEmail: String,
    customerPhoneNumber: String, // Added customer phone for technician view
    applianceType: { type: String, required: true },
    location: { type: String, required: true },
    scheduledDateTime: { type: Date, required: true },
    notes: String,
    status: { type: String, default: 'Pending', enum: ['Pending', 'Accepted', 'In Progress', 'Diagnosed', 'Paid', 'Completed', 'Cancelled'] },
    assignedTechnicianId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to the assigned technician User
    assignedTechnicianName: String,
    faultyParts: [String], // Parts identified as faulty by technician
    technicianRemarks: String, // Technician's diagnosis remarks
    quotation: {
        partCost: Number,
        laborCost: Number,
        travelCharges: Number,
        totalEstimate: Number,
        createdAt: Date
    },
    payment: {
        amount: Number,
        method: String,
        details: Object, // e.g., { transactionId: '...', last4: '1234' }
        status: { type: String, enum: ['Pending', 'Paid', 'Failed'], default: 'Pending' },
        paidAt: Date
    },
    completedAt: Date, // When the job was actually completed
    // New fields for review
    rating: { type: Number, min: 1, max: 5 },
    reviewText: String,
    reviewedAt: Date,
    proofImages: [String] // Array of Base64 encoded image strings for job completion proof
}, { timestamps: true }); // Automatically add createdAt and updatedAt fields

// Pre-save hook to update lastUpdated timestamp (handled by timestamps: true now, but good to have for custom updates)
jobSchema.pre('save', function(next) {
    this.lastUpdated = Date.now(); // This is automatically handled by `timestamps: true`
    next();
});

// Storage setup for Multer (using memory storage for file uploads for simplicity)
const storage = multer.memoryStorage(); // Use memory storage for demo
const upload = multer({ storage: storage }); // Initialize multer with the storage strategy


// Create the Job model from the schema
const Job = mongoose.model('Job', jobSchema);

// CORS configuration to allow requests from the frontend
app.use(cors({
    origin: 'http://localhost:5173', // ⚠️ IMPORTANT: Set this to your frontend's URL in production
    credentials: true // Allow cookies and authentication headers
}));

// --- Middleware ---
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request bodies

// Set trust proxy for deployment behind a proxy (like Render) to correctly identify client IP
app.set('trust proxy', 1);

// Configure express-session to store sessions in MongoDB
app.use(session({
    secret: SESSION_SECRET, // Secret key for signing the session ID cookie
    resave: false,          // Do not save session if unmodified
    saveUninitialized: false, // Do not save new sessions until something is stored
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: 'sessions', // Collection name to store session documents
        ttl: 24 * 60 * 60, // Session TTL (Time To Live) in seconds (24 hours)
        autoRemove: 'interval', // Remove expired sessions automatically
        autoRemoveInterval: 10 // Interval in minutes for auto-removal of expired sessions
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS only)
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        sameSite: 'lax', // Protects against CSRF attacks in a non-strict way
        maxAge: 24 * 60 * 60 * 1000 // Cookie lifespan (24 hours)
    }
}));

// Nodemailer transporter setup for sending emails
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use Gmail as the email service
    auth: {
        user: EMAIL_USER, // Your Gmail email address
        pass: EMAIL_PASS, // Your Gmail App Password
    },
});

// Global OTP storage (in-memory for simplicity).
// In a production environment, consider using a persistent store like Redis or a database for OTPs.
// Stores OTPs: email -> { otp: '123456', expiresAt: Date, type: 'signup' or 'password_reset' }
const otpStore = {};

// === OTP Generator Function ===
// Generates a random 6-digit number OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// === Send OTP Email Function ===
// Sends an email with the generated OTP
async function sendEmailOTP(email, otp, subject = 'Your TechSeva OTP', body = `Your One-Time Password (OTP) for TechSeva is: <strong>${otp}</strong><p>This OTP is valid for 5 minutes.</p>`) {
    // Check if email credentials are set in environment variables
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.error('Email credentials not set in environment variables. OTP email will not be sent.');
        return false;
    }
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: subject,
            html: body
        });
        console.log(`OTP ${otp} sent to ${email}`);
        return true;
    } catch (err) {
        console.error('Email sending failed:', err);
        return false;
    }
}

// === Middleware for Authentication Protection ===
// This middleware now correctly handles both API (JSON) and HTML page redirects.
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.id) {
        next(); // User is authenticated, proceed
    } else {
        // If the request expects HTML (e.g., direct page access in browser)
        if (req.accepts('html')) {
            console.log('Unauthenticated HTML request, redirecting to /');
            res.redirect('/'); // Redirect to the homepage (login/signup)
        } else {
            // For API requests (e.g., from fetch() in JavaScript)
            console.log('Unauthenticated API request, sending 401 JSON response.');
            res.status(401).json({ success: false, message: 'Unauthorized. Please login.', redirect: '/' });
        }
    }
}

// === Routes ===

// Serve the main index.html file as the homepage for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Serve static files from 'public' (CSS, JS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Serve specific HTML files WITH authentication and role checks
// These paths now use short names like /user, /technician etc.
app.get('/user', isAuthenticated, async (req, res) => {
    // Re-check user existence and role in case session data is stale or user was deleted
    const userInDb = await User.findById(req.session.user.id);
    if (!userInDb || (userInDb.role !== 'user' && userInDb.role !== 'admin')) { // Users and Admins can access user dashboard
        req.session.destroy(() => {
            res.redirect('/');
        });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

app.get('/technician', isAuthenticated, async (req, res) => {
    const userInDb = await User.findById(req.session.user.id);
    // Technicians need to be approved (kycStatus === 'approved') to access their dashboard
    if (!userInDb || (userInDb.role !== 'technician' && userInDb.role !== 'admin') || userInDb.kycStatus !== 'approved') {
        req.session.destroy(() => {
            res.redirect('/');
        });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'technician.html'));
});

app.get('/admin', isAuthenticated, async (req, res) => {
    const userInDb = await User.findById(req.session.user.id);
    if (!userInDb || userInDb.role !== 'admin') {
        req.session.destroy(() => {
            res.redirect('/');
        });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Example of other protected pages if they exist
app.get('/payment', isAuthenticated, async (req, res) => {
    const userInDb = await User.findById(req.session.user.id);
    if (!userInDb || (userInDb.role !== 'user' && userInDb.role !== 'admin')) {
        req.session.destroy(() => {
            res.redirect('/');
        });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'payment.html'));
});

app.get('/diagnosis', isAuthenticated, async (req, res) => {
    const userInDb = await User.findById(req.session.user.id);
    if (!userInDb || !['user', 'technician', 'admin'].includes(userInDb.role)) {
        req.session.destroy(() => {
            res.redirect('/');
        });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
});



// === API Routes ===

// API to get current logged-in user details
app.get('/api/user/me', isAuthenticated, async (req, res) => {
    try {
        // Fetch user from DB to get up-to-date user info, in case session is stale
        const currentUser = await User.findById(req.session.user.id).lean(); // Use .lean() for plain object
        if (currentUser) {
            // Only expose necessary user details, exclude sensitive info like password
            const { password, ...safeUser } = currentUser;
            res.json({ success: true, user: safeUser });
        } else {
            // User not found in DB (e.g., deleted), destroy session and force re-login
            req.session.destroy(err => {
                if (err) console.error('Session destruction error on user not found:', err);
                res.status(401).json({ success: false, message: 'User data not found. Please log in again.', redirect: '/' });
            });
        }
    } catch (err) {
        console.error('Error in /api/user/me:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching user details.' });
    }
});


// Send OTP for registration (first step of signup)
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required to send OTP.' });
        }
        // Check if user with this email already exists and is verified
        const existingUser = await User.findOne({ email });
        if (existingUser && existingUser.isVerified) {
            return res.status(409).json({ success: false, message: 'User with this email already exists and is verified. Please login.' });
        }

        const otp = generateOTP();
        otpStore[email] = { otp, expiresAt: Date.now() + 300000, type: 'signup' }; // OTP valid for 5 minutes
        console.log(`Generated OTP for ${email}: ${otp}`);

        const sent = await sendEmailOTP(email, otp, 'Your TechSeva Signup OTP', `<p>Your One-Time Password (OTP) for TechSeva signup is: <strong>${otp}</strong></p><p>This OTP is valid for 5 minutes.</p>`);
        if (sent) {
            return res.json({ success: true, message: `OTP sent to ${email}. Please check your email.` });
        } else {
            return res.status(500).json({ success: false, message: 'Failed to send OTP email. Please check server logs and Nodemailer configuration.' });
        }
    } catch (err) {
        console.error('Send OTP Error (Signup):', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP sending for signup.' });
    }
});

// Verify OTP (second step of signup)
app.post('/verify-otp', (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email and OTP are required for verification.' });
        }
        const storedOtpData = otpStore[email];
        if (!storedOtpData || storedOtpData.type !== 'signup') {
            return res.status(400).json({ success: false, message: 'No valid OTP found for this email or it is not a signup OTP.' });
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
        console.error('Verify OTP Error (Signup):', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP verification for signup.' });
    }
});

// User Registration (final step after OTP verification)
app.post('/register', async (req, res) => {
    try {
        const { fullName, email, phoneNumber, password, role, aadhaar, pan, bankDetails, skills } = req.body;

        if (!fullName || !email || !phoneNumber || !password || !role) {
            return res.status(400).json({ success: false, message: 'All required fields must be provided.' });
        }

        // Check for existing users by email or phone
        const existingUserByEmail = await User.findOne({ email });
        if (existingUserByEmail) {
            // If user exists but is not verified, update and verify them
            if (!existingUserByEmail.isVerified) {
                existingUserByEmail.fullName = fullName;
                existingUserByEmail.phoneNumber = phoneNumber;
                existingUserByEmail.password = password; // pre-save hook will hash
                existingUserByEmail.role = role;
                existingUserByEmail.isVerified = true;
                if (role === 'technician') {
                    existingUserByEmail.aadhaar = aadhaar;
                    existingUserByEmail.pan = pan;
                    // For bankDetails during registration, ensure it's an object
                    existingUserByEmail.bankDetails = {
                        bankName: bankDetails ? bankDetails.bankName : '',
                        accountNumber: bankDetails ? bankDetails.accountNumber : '',
                        ifscCode: bankDetails ? bankDetails.ifscCode : '',
                        upiId: bankDetails ? bankDetails.upiId : ''
                    };
                    existingUserByEmail.skills = skills ? skills.split(',').map(s => s.trim()) : [];
                    existingUserByEmail.kycStatus = 'pending';
                    existingUserByEmail.balance = existingUserByEmail.balance || 0; // Ensure balance is initialized
                } else {
                    existingUserByEmail.aadhaar = undefined; existingUserByEmail.pan = undefined;
                    existingUserByEmail.bankDetails = undefined; existingUserByEmail.skills = undefined;
                    existingUserByEmail.kycStatus = 'approved'; // Default non-tech users as approved
                }
                await existingUserByEmail.save();
                // Log in the user directly after update and verification
                req.session.user = {
                    id: existingUserByEmail._id.toString(),
                    fullName: existingUserByEmail.fullName,
                    email: existingUserByEmail.email,
                    role: existingUserByEmail.role,
                    kycStatus: existingUserByEmail.kycStatus
                };
                let redirectUrl = '/';
                if (existingUserByEmail.role === 'admin') redirectUrl = '/admin';
                else if (existingUserByEmail.role === 'technician') redirectUrl = '/technician';
                else if (existingUserByEmail.role === 'user') redirectUrl = '/user';
                return res.json({ success: true, message: `Welcome back! Account updated and verified.`, redirect: redirectUrl });

            } else {
                return res.status(409).json({ success: false, message: 'User with this email already exists and is verified. Please login.' });
            }
        }

        const existingUserByPhone = await User.findOne({ phoneNumber });
        if (existingUserByPhone) {
            return res.status(409).json({ success: false, message: 'User with this phone number already exists. Please login or use a different phone number.' });
        }

        const newUser = new User({
            fullName,
            email,
            phoneNumber,
            password: password, // Password will be hashed by pre-save hook
            role,
            isVerified: true, // Assumed true after client-sided OTP verification (this is the registration final step)
        });

        if (role === 'technician') {
            if (!aadhaar || !pan || !bankDetails || !skills) {
                // Modified: bankDetails is now an object, so check its properties if needed
                return res.status(400).json({ success: false, message: 'Technician registration requires Aadhaar, PAN, Bank Details, and Skills.' });
            }
            newUser.aadhaar = aadhaar;
            newUser.pan = pan;
            newUser.bankDetails = {
                bankName: bankDetails.bankName || '',
                accountNumber: bankDetails.accountNumber || '',
                ifscCode: bankDetails.ifscCode || '',
                upiId: bankDetails.upiId || ''
            };
            newUser.skills = skills.split(',').map(s => s.trim());
            newUser.kycStatus = 'pending'; // Explicitly set for new technicians
            newUser.balance = 0; // Initialize technician balance
        } else {
            newUser.kycStatus = 'approved'; // Default for users/admins, they don't need KYC
        }

        await newUser.save(); // Save the new user to MongoDB

        console.log("Registered User:", newUser);

        // Auto-login the new user after successful registration
        req.session.user = {
            id: newUser._id.toString(),
            fullName: newUser.fullName,
            email: newUser.email,
            role: newUser.role,
            kycStatus: newUser.kycStatus
        };

        let redirectUrl;
        switch (newUser.role) {
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
                redirectUrl = '/';
                break;
        }

        return res.json({
            success: true,
            message: `Registration successful for ${role}. You are now logged in.`,
            redirect: redirectUrl,
            user: req.session.user
        });

    } catch (err) {
        console.error('Registration Error:', err);
        if (err.code === 11000) { // Mongoose duplicate key error code
            let field = Object.keys(err.keyValue)[0];
            return res.status(409).json({ success: false, message: `A user with this ${field} already exists.` });
        }
        res.status(500).json({ success: false, message: 'Internal server error during registration.' });
    }
});

// User Login Route
app.post('/login', async (req, res) => {
    try {
        console.log('Received login request body:', req.body);
        const { email, password, role } = req.body;

        if (!email || !password || !role) {
            return res.status(400).json({ success: false, message: 'Email, password, and role are required for login.' });
        }

        const user = await User.findOne({ email }); // Find user by email first

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Check if the requested role matches the user's registered role
        if (user.role !== role) {
            return res.status(403).json({ success: false, message: `You are registered as a ${user.role}, not as a ${role}. Please select the correct role.` });
        }

        // Compare provided password with hashed password in DB
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        // Specific KYC check for technicians
        if (user.role === 'technician' && user.kycStatus !== 'approved') {
            let message = `Your technician application is currently ${user.kycStatus}.`;
            if (user.kycStatus === 'pending') {
                message += ' Please wait for approval to access technician features.';
            } else if (user.kycStatus === 'rejected') {
                message += ' Please contact support for more information.';
            }
            return res.status(403).json({ success: false, message: message });
        }

        // Set session user
        req.session.user = {
            id: user._id.toString(), // Use Mongoose _id and convert to string
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            kycStatus: user.kycStatus
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

        console.log(`User ${user.email} (${user.role}) logged in. Redirecting to ${redirectUrl}`);
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


// --- Forgot Password Endpoints ---

// Send Reset OTP: Initiates the password reset process by sending an OTP to the user's email
app.post('/send-reset-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    try {
        const user = await User.findOne({ email });
        // Security best practice: Do not reveal if the email exists or not.
        // Always send a success message to prevent user enumeration attacks.
        if (!user) {
            return res.json({ success: true, message: 'If this email is registered, a password reset OTP has been sent.' });
        }

        const otp = generateOTP(); // Generate a 6-digit number OTP
        // Store OTP with an expiration time (10 minutes) and type 'password_reset'
        otpStore[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000, type: 'password_reset' };

        const emailBody = `<p>Your One-Time Password (OTP) for password reset is: <strong>${otp}</strong></p>
                           <p>This OTP is valid for 10 minutes.</p>
                           <p>If you did not request a password reset, please ignore this email.</p>`;

        const sent = await sendEmailOTP(email, otp, 'TechSeva Password Reset OTP', emailBody);

        if (sent) {
            res.json({ success: true, message: 'Password reset OTP sent to your email.' });
        } else {
            res.status(500).json({ success: false, message: 'Failed to send password reset OTP. Please try again.' });
        }

    } catch (error) {
        console.error('Error sending reset OTP:', error);
        res.status(500).json({ success: false, message: 'Server error while sending reset OTP.' });
    }
});

// Reset Password: Verifies the OTP and updates the user's password
app.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Validate required fields
    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    // Validate new password strength
    if (newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'New password must be at least 8 characters long.' });
    }

    const storedOtpData = otpStore[email];

    // Validate OTP against stored data (existence, correctness, expiration, type)
    if (!storedOtpData || storedOtpData.otp !== otp || Date.now() > storedOtpData.expiresAt || storedOtpData.type !== 'password_reset') {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Update user's password. The pre-save hook will hash it automatically.
        user.password = newPassword;
        await user.save();

        delete otpStore[email]; // Clear OTP after successful password reset

        res.json({ success: true, message: 'Your password has been reset successfully. You can now log in with your new password.' });

    } catch (error) {
        console.error('Password Reset Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error during password reset.' });
    }
});


// --- Service/Job Management API Routes ---

// Book Service API for Users
app.post('/api/book-service', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can book services.' });
        }

        const { applianceType, location, scheduledDateTime, notes } = req.body;

        if (!applianceType || !location || !scheduledDateTime) {
            return res.status(400).json({ success: false, message: 'Appliance type, location, and scheduled date/time are required for booking.' });
        }

        // Find available technicians (approved KYC)
        const availableTechnicians = await User.find({ role: 'technician', kycStatus: 'approved' });
        // Assign a random available technician, or null if none are available
        const assignedTechnician = availableTechnicians.length > 0 ? availableTechnicians[Math.floor(Math.random() * availableTechnicians.length)] : null;

        const customer = await User.findById(req.session.user.id);
        if (!customer) {
            return res.status(404).json({ success: false, message: 'Logged-in user not found in database.' });
        }

        // Generate a simple unique job ID (e.g., J + last 6 digits of timestamp)
        const newJobId = `J${Date.now().toString().slice(-6)}${Math.floor(Math.random() * 100)}`; // Add random suffix for higher uniqueness

        const newJob = new Job({
            jobId: newJobId, // Custom ID for display
            userId: customer._id, // Mongoose ObjectId
            customerName: customer.fullName,
            customerEmail: customer.email,
            customerPhoneNumber: customer.phoneNumber, // Include customer phone
            applianceType,
            location,
            scheduledDateTime,
            notes,
            status: 'Pending',
            assignedTechnicianId: assignedTechnician ? assignedTechnician._id : null,
            assignedTechnicianName: assignedTechnician ? assignedTechnician.fullName : 'Pending Assignment',
        });

        await newJob.save();

        res.json({ success: true, message: 'Booking request received successfully. A technician will be assigned soon.', jobId: newJob.jobId });
    } catch (err) {
        console.error('Book Service Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during service booking.' });
    }
});

// Technician Job List API: Fetch jobs for the logged-in technician
app.get('/api/technician/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician' && req.session.user.role !== 'admin') { // Admin can also view all tech jobs
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians or admins can view technician jobs.' });
        }
        if (req.session.user.role === 'technician' && req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot view jobs.' });
        }

        const technicianObjectId = new mongoose.Types.ObjectId(req.session.user.id);

        // Fetch all jobs ever assigned to this technician, regardless of status.
        // This provides a complete history for frontend calculations.
        const technicianJobs = await Job.find({ assignedTechnicianId: technicianObjectId })
            .populate('userId', 'fullName email phoneNumber') // Populate customer info
            .lean(); // .lean() to get plain JS objects

        res.json({ success: true, jobs: technicianJobs });
    } catch (err) {
        console.error('Fetch Technician Jobs Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching technician jobs.' });
    }
});

// Technician Accept Job API - MODIFIED LOGIC HERE
app.post('/api/technician/jobs/accept', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can accept jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot accept jobs.' });
        }

        const { jobId } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.session.user.id);
        const technicianName = req.session.user.fullName;

        // Find the job by its custom 'jobId', ensure it's 'Pending'
        // Allow acceptance if unassigned (assignedTechnicianId: null) OR already assigned to this specific technician
        const job = await Job.findOneAndUpdate(
            {
                jobId: jobId,
                status: 'Pending',
                $or: [
                    { assignedTechnicianId: null }, // Job is unassigned
                    { assignedTechnicianId: technicianObjectId } // Job is assigned to this technician
                ]
            },
            { $set: { assignedTechnicianId: technicianObjectId, assignedTechnicianName: technicianName, status: 'Accepted' } },
            { new: true } // Return the updated document
        ).lean();

        if (job) {
            res.json({ success: true, message: 'Job accepted successfully!', job: job });
        } else {
            // This message now correctly covers cases where it's not pending OR not unassigned/assigned to current tech
            res.status(404).json({ success: false, message: 'Job not found, not in pending status, or already assigned.' });
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
        const technicianObjectId = new mongoose.Types.ObjectId(req.session.user.id);

        // Find the job and update its status to 'In Progress' if it was 'Accepted' and assigned to this technician
        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianObjectId, status: 'Accepted' },
            { $set: { status: 'In Progress' } },
            { new: true }
        ).lean();

        if (job) {
            res.json({ success: true, message: 'Job status updated to In Progress!', job: job });
        } else {
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in Accepted status.' });
        }
    } catch (err) {
        console.error('Start Job Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job start.' });
    }
});

// Technician Complete Job API (Now also handles proof images and adds to balance)
app.post('/api/technician/jobs/complete', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can complete jobs.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot complete jobs.' });
        }

        const { jobId, proofImages } = req.body; // Expect proofImages (Base64 array)
        const technicianId = req.session.user.id; 

        // Find the job and update its status to 'Completed' and save proof images
        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianId, status: { $in: ['In Progress', 'Diagnosed'] } },
            {
                $set: {
                    status: 'Completed',
                    completedAt: new Date(),
                    proofImages: proofImages || []
                }
            },
            { new: true } // Return the updated document
        );

        if (job) {
            // After successful completion, if the job has a quotation, add to technician's balance
            // NOTE: Balance is now updated on the /api/process-payment endpoint when the customer pays.
            // This section here primarily marks the job as completed.

            res.json({ success: true, message: 'Job marked as Completed and proof images saved!', job: job.toJSON() });
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
        const job = await Job.findOne({ jobId: jobId }).lean(); // Use jobId for the custom ID field

        if (job) {
            const jobUserIdStr = job.userId ? job.userId.toString() : null;
            const jobAssignedTechIdStr = job.assignedTechnicianId ? job.assignedTechnicianId.toString() : null;

            // Check if current user is admin, the job's customer, or the assigned technician
            if (req.session.user.role === 'admin' || jobUserIdStr === req.session.user.id || jobAssignedTechIdStr === req.session.user.id) {
                const customer = await User.findById(job.userId).lean();
                const technician = job.assignedTechnicianId ? await User.findById(job.assignedTechnicianId).lean() : null;

                const jobDetails = {
                    ...job,
                    customerName: customer ? customer.fullName : 'N/A',
                    customerEmail: customer ? customer.email : 'N/A', // Added email
                    customerPhoneNumber: customer ? customer.phoneNumber : 'N/A',
                    technicianName: technician ? technician.fullName : 'N/A',
                    technicianEmail: technician ? technician.email : 'N/A', // Added email
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
app.post('/api/technician/diagnosis', isAuthenticated, upload.array('appliancePhotos'), async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can submit diagnosis.' });
        }
        if (req.session.user.kycStatus !== 'approved') {
            return res.status(403).json({ success: false, message: 'Your KYC is not yet approved. You cannot submit diagnosis.' });
        }

        const { jobId, faultyParts, technicianRemarks, partCost, laborCost, travelCharges, totalEstimate } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.session.user.id);

        // Debug log: see if files are received
        console.log('Files received:', req.files);

        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianObjectId, status: { $in: ['In Progress', 'Accepted'] } },
            {
                $set: {
                    faultyParts,
                    technicianRemarks,
                    quotation: {
                        partCost: parseFloat(partCost),
                        laborCost: parseFloat(laborCost),
                        travelCharges: parseFloat(travelCharges),
                        totalEstimate: parseFloat(totalEstimate),
                        createdAt: new Date()
                    },
                    status: 'Diagnosed'
                }
            },
            { new: true }
        ).lean();

        if (job) {
            res.json({ success: true, message: 'Diagnosis & Quotation saved successfully.', job });
        } else {
            res.status(404).json({ success: false, message: 'Job not found or not assigned to you.' });
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
        const userObjectId = new mongoose.Types.ObjectId(req.session.user.id);
        const userJobs = await Job.find({ userId: userObjectId }).lean();

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
        const userObjectId = new mongoose.Types.ObjectId(req.session.user.id);

        // Allow cancellation only if job is 'Pending' or 'Accepted' and owned by the user
        const job = await Job.findOneAndUpdate(
            { jobId: jobId, userId: userObjectId, status: { $in: ['Pending', 'Accepted'] } },
            { $set: { status: 'Cancelled' } },
            { new: true }
        ).lean();

        if (job) {
            res.json({ success: true, message: 'Job cancelled successfully!' });
        } else {
            res.status(404).json({ success: false, message: 'Job not found, not associated with your account, or cannot be cancelled at its current status.' });
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

        const job = await Job.findOne({ jobId: jobId }); // Use jobId for the custom ID field

        if (!job) {
            console.warn(`[PAYMENT] Job ${jobId} not found for payment processing.`);
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const jobUserIdStr = job.userId ? job.userId.toString() : null;

        // Only the customer who owns the job or an admin can process payment
        if (jobUserIdStr !== req.session.user.id && req.session.user.role !== 'admin') {
            console.warn(`[PAYMENT] Access denied for payment on job ${jobId}. User role: ${req.session.user.role}, Job owner: ${jobUserIdStr}`);
            return res.status(403).json({ success: false, message: 'Access denied to process payment for this job.' });
        }

        // Payments allowed only for 'Diagnosed' or 'Completed' jobs
        if (job.status !== 'Diagnosed' && job.status !== 'Completed') {
            console.warn(`[PAYMENT] Payment not allowed for job ${jobId}. Current status: ${job.status}.`);
            return res.status(400).json({ success: false, message: `Payment can only be processed for jobs that are 'Diagnosed' or 'Completed'. Current status: ${job.status}.` });
        }

        if (!totalAmount || !paymentMethod) {
            console.warn(`[PAYMENT] Missing totalAmount or paymentMethod for job ${jobId}.`);
            return res.status(400).json({ success: false, message: 'Total amount and payment method are required.' });
        }

        // Simulate payment processing
        console.log(`[PAYMENT] Processing payment for Job ID: ${jobId}, Amount: ${totalAmount}, Method: ${paymentMethod}`);
        console.log(`[PAYMENT] Payment Details:`, paymentDetails);


        job.payment = {
            amount: parseFloat(totalAmount),
            method: paymentMethod,
            details: paymentDetails,
            status: 'Paid',
            paidAt: new Date()
        };
        job.status = 'Paid'; // Update job status to Paid

        await job.save();

        // --- NEW LOGIC: Update technician's balance upon successful payment ---
        if (job.assignedTechnicianId && job.quotation && job.quotation.totalEstimate) {
            const APP_COMMISSION_RATE = 0.10; // 10% app commission
            const TAX_RATE_INDIA = 0.18; // Sample GST rate for services (18%)

            const grossAmount = job.quotation.totalEstimate;
            const appCommission = grossAmount * APP_COMMISSION_RATE;
            const amountBeforeTax = grossAmount - appCommission;
            const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
            const technicianNetEarning = amountBeforeTax - technicianTaxDeduction;

            console.log(`[BALANCE UPDATE - on Payment] Job ${job.jobId} paid. Calculated Net Earning for technician: ₹${technicianNetEarning.toFixed(2)}`);

            if (technicianNetEarning > 0) {
                try {
                    const updatedTechnician = await User.findByIdAndUpdate(
                        job.assignedTechnicianId,
                        { $inc: { balance: technicianNetEarning } },
                        { new: true } // Return the updated document
                    );
                    if (updatedTechnician) {
                        console.log(`[BALANCE UPDATE - on Payment] Technician ${updatedTechnician._id} balance updated to: ₹${updatedTechnician.balance.toFixed(2)}`);
                    } else {
                        console.error(`[BALANCE UPDATE ERROR - on Payment] Technician ${job.assignedTechnicianId} not found when trying to update balance.`);
                    }
                } catch (updateError) {
                    console.error(`[BALANCE UPDATE ERROR - on Payment] Failed to update technician ${job.assignedTechnicianId} balance for job ${job.jobId}:`, updateError);
                }
            } else {
                console.log(`[BALANCE UPDATE INFO - on Payment] Net Earning for job ${job.jobId} is zero or negative. Technician balance not incremented.`);
            }
        } else {
            console.log(`[BALANCE UPDATE INFO - on Payment] Job ${job.jobId} has no assigned technician or quotation. Technician balance not incremented.`);
        }
        // --- END NEW LOGIC ---

        console.log(`[PAYMENT] Job ${jobId} successfully marked as Paid. Technician ${job.assignedTechnicianId} should receive earnings shortly.`);

        res.json({ success: true, message: 'Payment processed successfully and job marked as Paid!', job: job.toJSON() });

    } catch (err) {
        console.error('Process Payment Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during payment processing.' });
    }
});


// --- Admin API Routes ---

// Admin API: Get All Users
app.get('/api/admin/users', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only administrators can view users.' });
        }
        // Fetch all users, select all fields except password for security
        const users = await User.find().select('-password').lean();
        res.json({ success: true, users: users });
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

        const totalJobs = await Job.countDocuments();
        const activeTechnicians = await User.countDocuments({ role: 'technician', kycStatus: 'approved' });

        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0); // Last day of current month

        // Aggregate to calculate total revenue for the current month from paid jobs
        const revenueThisMonthResult = await Job.aggregate([
            {
                $match: {
                    'payment.status': 'Paid',
                    'payment.paidAt': {
                        $gte: startOfMonth,
                        $lte: endOfMonth
                    }
                }
            },
            {
                $group: {
                    _id: null, // Group all matching documents into a single group
                    totalRevenue: { $sum: '$payment.amount' } // Sum the payment amount
                }
            }
        ]);

        const revenueThisMonth = revenueThisMonthResult.length > 0 ? revenueThisMonthResult[0].totalRevenue : 0;

        const pendingApprovals = await User.countDocuments({ role: 'technician', kycStatus: 'pending' });

        res.json({
            success: true,
            data: {
                totalJobs,
                activeTechnicians,
                revenueThisMonth: parseFloat(revenueThisMonth.toFixed(2)), // Format to 2 decimal places
                pendingApprovals
            }
        });

    } catch (err) {
        console.error('Admin Dashboard Overview Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching dashboard overview.' });
    }
});

// Admin API: Get All Jobs (Enhanced with populated customer/technician details)
app.get('/api/admin/jobs', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only administrators can view all jobs.' });
        }
        const jobs = await Job.find()
            .populate('userId', 'fullName email phoneNumber') // Populate customer details
            .populate('assignedTechnicianId', 'fullName email phoneNumber') // Populate technician details
            .lean(); // Get plain JS objects

        // Map over jobs to flatten populated data and ensure consistent field names
        const enhancedJobs = jobs.map(job => ({
            ...job,
            customerName: job.userId ? job.userId.fullName : 'N/A',
            customerEmail: job.userId ? job.userId.email : 'N/A',
            customerPhoneNumber: job.userId ? job.userId.phoneNumber : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Pending Assignment',
            technicianEmail: job.assignedTechnicianId ? job.assignedTechnicianId.email : 'N/A',
            technicianPhoneNumber: job.assignedTechnicianId ? job.assignedTechnicianId.phoneNumber : 'N/A',
            userId: job.userId ? job.userId._id.toString() : null, // Ensure ID is string for consistency
            assignedTechnicianId: job.assignedTechnicianId ? job.assignedTechnicianId._id.toString() : null // Ensure ID is string
        }));

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

        const job = await Job.findOne({ jobId: jobId }); // Use jobId for the custom ID field
        if (!job) {
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const technician = await User.findById(technicianId);
        // Ensure the assigned user is an approved technician
        if (!technician || technician.role !== 'technician' || technician.kycStatus !== 'approved') {
            return res.status(404).json({ success: false, message: 'Technician not found or not an approved technician.' });
        }

        job.assignedTechnicianId = technician._id;
        job.assignedTechnicianName = technician.fullName;
        // If the job was pending, change its status to Accepted upon manual assignment
        if (job.status === 'Pending') {
            job.status = 'Accepted';
        }

        await job.save(); // Save the updated job

        res.json({ success: true, message: `Technician ${technician.fullName} assigned to job ${jobId}.`, job: job.toJSON() });

    } catch (err) {
        console.error('Admin Assign Technician Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while assigning technician.' });
    }
});

// Admin API: Grant Technician KYC Approval
app.post('/api/admin/users/:userId/grant-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can modify user roles.' });
        }

        const userId = req.params.userId;
        const user = await User.findById(userId);

        if (!user || user.role !== 'technician') {
            return res.status(404).json({ success: false, message: 'User not found or not a technician role.' });
        }

        if (user.kycStatus === 'approved') {
            return res.status(400).json({ success: false, message: 'Technician is already approved.' });
        }

        user.kycStatus = 'approved';
        await user.save();
        res.json({ success: true, message: 'Technician KYC approved successfully.', user: user.toJSON() });
    }
    catch (err) {
        console.error('Admin Grant Technician Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while granting technician KYC approval.' });
    }
});

// Admin API: Reject Technician KYC
app.post('/api/admin/users/:userId/reject-technician', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied. Only admins can reject technician KYC.' });
        }

        const userId = req.params.userId;
        const user = await User.findById(userId);

        if (!user || user.role !== 'technician') {
            return res.status(404).json({ success: false, message: 'User not found or not a technician role.' });
        }

        if (user.kycStatus === 'rejected') {
            return res.status(400).json({ success: false, message: 'Technician KYC is already rejected.' });
        }

        user.kycStatus = 'rejected';
        await user.save();
        res.json({ success: true, message: 'Technician KYC rejected successfully.', user: user.toJSON() });
    } catch (err) {
        console.error('Admin Reject Technician KYC Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error while rejecting technician KYC.' });
    }
});


// --- Logout Route ---
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


// --- AI Diagnosis Endpoint (Backend Integration with Gemini API) ---
app.post('/api/ai-diagnosis', async (req, res) => {
    const { problemDescription } = req.body;

    if (!problemDescription) {
        return res.status(400).json({ success: false, message: 'Problem description is required for AI diagnosis.' });
    }

    try {
        // Construct chat history for the Gemini API call
        let chatHistory = [];
        chatHistory.push({ role: "user", parts: [{ text: `Provide a concise, preliminary diagnosis for an appliance problem. User input: "${problemDescription}". Suggest possible causes and basic troubleshooting steps. Keep it under 200 words.` }] });

        const payload = { contents: chatHistory };
        // Get API key from environment variables
        const apiKey = process.env.API_KEY; 

        if (!apiKey) {
            console.error('CRITICAL ERROR: Gemini API Key (API_KEY) not set in environment variables!');
            return res.status(500).json({ success: false, message: 'Server-side API key for AI diagnosis is missing. Please configure it.' });
        }

        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

        // Make the fetch call to the Gemini API
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        // --- NEW: Add detailed logging for Gemini API response structure ---
        console.log('Full Gemini API Response:', JSON.stringify(result, null, 2));

        // Extract the diagnosis text from the Gemini API response
        if (result.candidates && result.candidates.length > 0) {
            const firstCandidate = result.candidates[0];
            if (firstCandidate.content && firstCandidate.content.parts && firstCandidate.content.parts.length > 0) {
                const diagnosisText = firstCandidate.content.parts[0].text;
                res.json({ success: true, diagnosis: diagnosisText });
            } else {
                console.error('Gemini API Response Error: Candidate content or parts missing.', JSON.stringify(firstCandidate, null, 2));
                // Check for `safetyRatings` or `promptFeedback`
                if (firstCandidate.safetyRatings && firstCandidate.safetyRatings.some(rating => rating.blocked)) {
                     res.status(400).json({ success: false, message: 'AI diagnosis blocked due to safety concerns with the input. Please rephrase.' });
                } else {
                    res.status(500).json({ success: false, message: 'Failed to get AI diagnosis from the model. Unexpected content structure within candidate.' });
                }
            }
        } else {
            console.error('Gemini API Response Error: No candidates found.', JSON.stringify(result, null, 2));
            if (result.promptFeedback && result.promptFeedback.safetyRatings && result.promptFeedback.safetyRatings.some(rating => rating.blocked)) {
                res.status(400).json({ success: false, message: 'AI diagnosis blocked due to safety concerns with the input. Please rephrase.' });
            } else {
                res.status(500).json({ success: false, message: 'Failed to get AI diagnosis from the model. No candidates or unexpected top-level structure.' });
            }
        }
    } catch (error) {
        console.error('Backend AI Diagnosis API error:', error);
        res.status(500).json({ success: false, message: 'Server error during AI diagnosis.' });
    }
});

// --- API Route for Submitting User Review ---
app.post('/api/user/submit-review', isAuthenticated, async (req, res) => {
    try {
        // Ensure only users can submit reviews
        if (req.session.user.role !== 'user') {
            return res.status(403).json({ success: false, message: 'Access denied. Only users can submit reviews.' });
        }

        const { jobId, rating, reviewText } = req.body;
        const userId = req.session.user.id;

        // Basic validation
        if (!jobId || rating === undefined || rating < 1 || rating > 5 || !reviewText) {
            return res.status(400).json({ success: false, message: 'Job ID, rating (1-5), and review text are required.' });
        }

        // Find the job associated with the logged-in user
        const job = await Job.findOne({ jobId: jobId, userId: userId });

        if (!job) {
            return res.status(404).json({ success: false, message: 'Job not found or not associated with your account.' });
        }

        // Prevent multiple reviews for the same job or review of jobs not completed/paid
        if (job.rating || job.reviewedAt) {
            return res.status(400).json({ success: false, message: 'This job has already been reviewed.' });
        }
        if (job.status !== 'Completed' && job.status !== 'Paid') {
            return res.status(400).json({ success: false, message: 'Only completed or paid jobs can be reviewed.' });
        }

        // Update the job with the review details
        job.rating = rating;
        job.reviewText = reviewText;
        job.reviewedAt = new Date(); // Timestamp when the review was submitted

        await job.save();

        // After saving the review, update the technician's average rating
        const technician = await User.findById(job.assignedTechnicianId);
        if (technician) {
            // Recalculate average rating
            const allTechnicianJobs = await Job.find({ assignedTechnicianId: technician._id, rating: { $exists: true, $ne: null } });
            let totalRating = 0;
            allTechnicianJobs.forEach(techJob => {
                totalRating += techJob.rating;
            });
            technician.averageRating = allTechnicianJobs.length > 0 ? totalRating / allTechnicianJobs.length : 0;
            technician.ratingCount = allTechnicianJobs.length; // Update count of rated jobs
            await technician.save();
        }

        res.json({ success: true, message: 'Review submitted successfully!' });

    } catch (err) {
        console.error('Submit Review API Error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during review submission.' });
    }
});


// --- NEW: API for updating technician's availability settings
app.post('/api/technician/update-availability', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can update availability.' });
        }

        const userId = req.session.user.id;
        const { availableDays, startTime, endTime, emergencyCalls } = req.body;

        const technician = await User.findById(userId);
        if (!technician) {
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        technician.availability = {
            availableDays: availableDays || [],
            startTime: startTime || '09:00',
            endTime: endTime || '18:00',
            emergencyCalls: emergencyCalls !== undefined ? emergencyCalls : false
        };
        await technician.save();

        res.json({ success: true, message: 'Availability updated successfully!' });

    } catch (error) {
        console.error('Update Availability API Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating availability.' });
    }
});

// --- NEW: API for updating technician's working location and service radius
app.post('/api/technician/update-location', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can update location settings.' });
        }

        const userId = req.session.user.id;
        const { workingLocation } = req.body; // { address: String, radiusKm: Number }

        const technician = await User.findById(userId);
        if (!technician) {
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        technician.workingLocation = {
            address: workingLocation.address || '',
            radiusKm: workingLocation.radiusKm || 0,
            latitude: workingLocation.latitude, // Can be undefined
            longitude: workingLocation.longitude // Can be undefined
        };
        await technician.save();

        res.json({ success: true, message: 'Location settings updated successfully!' });

    } catch (error) {
        console.error('Update Location API Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating location settings.' });
    }
});

// --- NEW: API for updating technician's bank/UPI payment details
app.post('/api/technician/update-payment-details', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can update payment details.' });
        }

        const userId = req.session.user.id;
        const { bankName, accountNumber, ifscCode, upiId } = req.body;

        const technician = await User.findById(userId);
        if (!technician) {
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        // --- Explicitly set the entire bankDetails object ---
        // This ensures the field is treated as an object, overriding any previous string data
        technician.bankDetails = {
            bankName: bankName || '',
            accountNumber: accountNumber || '',
            ifscCode: ifscCode || '',
            upiId: upiId || ''
        };
        // --- END Explicit set ---

        console.log(`[PAYMENT DETAILS] Technician ${userId} bankDetails BEFORE save:`, technician.bankDetails);
        await technician.save();
        console.log(`[PAYMENT DETAILS] Technician ${userId} bankDetails AFTER save:`, technician.bankDetails);


        res.json({ success: true, message: 'Payment details updated successfully!' });

    } catch (error) {
        console.error('[PAYMENT DETAILS ERROR] Update Payment Details API Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating payment details.' });
    }
});

// --- NEW: API for technician withdrawal (now deducts from balance)
app.post('/api/technician/withdraw', isAuthenticated, async (req, res) => {
    try {
        if (req.session.user.role !== 'technician') {
            return res.status(403).json({ success: false, message: 'Access denied. Only technicians can initiate withdrawals.' });
        }

        const userId = req.session.user.id;
        const { amount } = req.body; 

        if (amount <= 0) {
            return res.status(400).json({ success: false, message: 'Withdrawal amount must be positive.' });
        }

        const technician = await User.findById(userId);
        if (!technician) {
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        if (technician.balance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance for withdrawal.' });
        }

        // Check if payment details are available (bank account OR UPI ID)
        const hasBankDetails = technician.bankDetails && technician.bankDetails.accountNumber && technician.bankDetails.bankName && technician.bankDetails.ifscCode;
        const hasUpiId = technician.bankDetails && technician.bankDetails.upiId;

        if (!hasBankDetails && !hasUpiId) {
            return res.status(400).json({ success: false, message: 'Please provide either complete bank account details or a UPI ID before withdrawing.' });
        }
        
        // Deduct the amount from the technician's balance
        technician.balance -= amount;
        await technician.save();
        
        res.json({ success: true, message: `Withdrawal of ₹${amount.toFixed(2)} initiated successfully. Your new balance is ₹${technician.balance.toFixed(2)}. Processing may take 1-2 business days.` });

    } catch (error) {
        console.error('[WITHDRAWAL ERROR] Withdrawal API Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error during withdrawal.' });
    }
});


// --- Catch-all 404 Route - Must be placed at the very end ---
app.use((req, res, next) => {
    // For HTML requests, serve a 404 HTML page
    if (req.accepts('html')) {
    return res.status(404).sendFile(
        path.join(__dirname, 'views', '404.html'),
        (err) => {
            if (err) {
                return res.status(404).send('<h1>404 - Page Not Found</h1>');
            }
        }
    );
}
// For API requests or other types, send a JSON 404
    res.status(404).json({ success: false, message: 'API endpoint not found.' });
});


// --- Start the server ---
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log('✅ Connected to MongoDB Atlas. Data will now persist!');
    console.log('Remember to set MONGODB_URI, EMAIL_USER, EMAIL_PASS, and SESSION_SECRET in your Render environment variables!');
});
