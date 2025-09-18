// server.js

// Load environment variables from .env file
require('dotenv').config();

// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo'); // For storing sessions in MongoDB
const nodemailer = require('nodemailer'); // For sending emails (e.g., OTP)
const bcrypt = require('bcryptjs'); // For password hashing
const crypto = require('crypto'); // For generating random OTPs
const path = require('path'); // Node.js path module for serving static files
const multer = require('multer'); // For handling multipart/form-data, primarily file uploads
const cors = require('cors'); // For enabling Cross-Origin Resource Sharing
const { OAuth2Client } = require('google-auth-library'); // Import Google Auth Library for token verification
const { createObjectCsvWriter } = require('csv-writer'); // For CSV export
const fs = require('fs'); // Node's file system module

// Initialize Express app
const app = express();

// --- Global Constants ---
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI; // MongoDB Atlas connection string
const SESSION_SECRET = process.env.SESSION_SECRET || 'supersecretkeyforprod'; // Use a strong, random key in production
const EMAIL_USER = process.env.EMAIL_USER; // Your Gmail email address for sending OTPs
const EMAIL_PASS = process.env.EMAIL_PASS; // Your Gmail App Password for sending OTPs
const GOOGLE_MAPS_API_KEY = process.env.VITE_GOOGLE_MAPS_API_KEY; 
const GEMINI_API_KEY = process.env.API_KEY; // API Key for AI Model (Gemini)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID; // Google Sign-in Client ID

// Commission and Tax Rates
const APP_COMMISSION_RATE = 0.10; // 10%
const TAX_RATE_INDIA = 0.18; // 18% GST

console.log('Server is reading GOOGLE_CLIENT_ID:', GOOGLE_CLIENT_ID);
console.log('Server is reading VITE_GOOGLE_MAPS_API_KEY:', GOOGLE_MAPS_API_KEY ? '******' : 'Not set');

// Initialize Google OAuth2Client for token verification
let googleAuthClient;
if (GOOGLE_CLIENT_ID) {
    googleAuthClient = new OAuth2Client(GOOGLE_CLIENT_ID);
} else {
    console.warn('GOOGLE_CLIENT_ID environment variable not set! Google login will not function.');
}

// --- MongoDB Connection ---
if (!MONGODB_URI) {
    console.error('CRITICAL ERROR: MONGODB_URI environment variable not set!');
    console.error('Please set MONGODB_URI in your Render environment variables or .env file.');
    process.exit(1); // Exit if no MongoDB URI is provided
}

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true, // Deprecated, but good to keep for clarity for older versions
    useUnifiedTopology: true, // Deprecated, but good to keep for clarity for older versions
    serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s for server selection
    socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
})
.then(() => {
    console.log('✅ MongoDB Connected successfully!');
})
.catch(err => {
    console.error('❌ MongoDB connection error on initial connect:', err);
    process.exit(1);
});

// Mongoose connection event listeners for better debugging
mongoose.connection.on('connected', () => {
    console.log('✅ Mongoose connected to DB!');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ Mongoose connection error during operation:', err);
});

mongoose.connection.on('disconnected', () => {
    console.warn('⚠️ Mongoose disconnected from DB. This might indicate network issues or idle timeouts.');
});

// --- Mongoose Schemas and Models ---

// User Schema - Centralized for all user types (customer, technician, admin roles)
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false }, // Password can be null for Google Sign-in users
    phoneNumber: { type: String, sparse: true }, // sparse allows nulls but enforces uniqueness for non-nulls
    otp: { type: String }, // For OTP verification flows
    otpExpires: { type: Date }, // Expiry for OTP
    googleId: { type: String, unique: true, sparse: true }, // For Google Sign-in
    role: { type: String, enum: ['user', 'technician', 'Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent'], default: 'user' }, // Corrected roles
    isVerified: { type: Boolean, default: false }, // For email/phone verification
    profilePictureUrl: { type: String, default: 'https://placehold.co/120x120/E9ECEF/495057?text=U' },
    // Removed: address: { type: String }, // General user address
    // Removed: city: { type: String }, // General user city
    
    // START: NEW Structured Address for the user's profile
    address: { 
        pincode: { type: String },
        state: { type: String },
        city: { type: String },
        houseBuilding: { type: String },
        street: { type: String },
        latitude: { type: Number },
        longitude: { type: Number }
    },
    // END: NEW Structured Address
    
    // Technician specific fields (ये फ़ील्ड ऐसे ही रहेंगे)
    skills: [{ type: String }], // e.g., ['AC Repair', 'Plumbing']
    experience: { type: Number, default: 0 }, // Years of experience
    averageRating: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 },
    jobsCompleted: { type: Number, default: 0 },
    kycStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }, // KYC status for technicians
    pan: { type: String, unique: true, sparse: true }, // PAN number for technicians
    aadhaar: { type: String, unique: true, sparse: true }, // Aadhaar number for technicians
    workingLocation: { // For technicians' service area
    pincode: { type: String },
    city: { type: String },
    state: { type: String },
    street: { type: String },
    houseBuilding: { type: String },
    radiusKm: { type: Number, default: 10 }, // New field for service radius
    latitude: { type: Number },
    longitude: { type: Number }
    },
    availability: { // For technicians' working hours
        availableDays: [String], // e.g., ['Monday', 'Wednesday']
        startTime: String, // e.g., '09:00'
        endTime: String, // e.g., '18:00'
        emergencyCalls: { type: Boolean, default: false }
    },

    // Admin specific fields (for Citymanager, Serviceadmin)
    assignedCities: [{ type: String }], // For Citymanager
    
    status: { type: String, enum: ['active', 'suspended', 'pending'], default: 'active' }, // For all user types
    balance: { type: Number, default: 0 }, // For technicians to track earnings
    bankDetails: { // For technician payouts
        bankName: { type: String },
        accountNumber: { type: String },
        ifscCode: { type: String },
        upiId: { type: String }
    }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (this.isModified('password') && this.password) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    // Set kycStatus to 'pending' for new technicians, 'approved' for new users (if not explicitly set)
    if (this.isNew) {
        if (this.role === 'technician' && !this.kycStatus) {
            this.kycStatus = 'pending';
        } else if (this.role === 'user' && !this.kycStatus) {
            this.kycStatus = 'approved';
        }
    }
    next();
});

// Method to compare password
userSchema.methods.comparePassword = function(candidatePassword) {
    if (this.password) {
        return bcrypt.compare(candidatePassword, this.password);
    }
    return Promise.resolve(false);
};

const User = mongoose.model('User', userSchema);

// Appliance Type Schema
const applianceTypeSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String },
    isActive: { type: Boolean, default: true },
    basePrice: { type: Number, default: 0 }, // Default base price for the service
    commissionRate: { type: Number, default: APP_COMMISSION_RATE } // Default commission rate for this service
}, { timestamps: true });
const ApplianceType = mongoose.model('ApplianceType', applianceTypeSchema);


// Location Schema (for cities/service areas)
const locationSchema = new mongoose.Schema({
    city: { type: String, required: true, unique: true },
    state: { type: String },
    country: { type: String, default: 'India' },
    pincodes: [{ type: String }],
    status: { type: String, enum: ['active', 'inactive'], default: 'active' }
}, { timestamps: true });
const Location = mongoose.model('Location', locationSchema);


// Job Schema
// Job Schema
const jobSchema = new mongoose.Schema({
    jobId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    customerName: String,
    customerEmail: String,
    customerPhoneNumber: String,
    applianceType: { type: String, required: true },
    problemDescription: String,
    // START: NEW Structured Location for the job
    location: {
        pincode: { type: String },
        state: { type: String },
        city: { type: String },
        houseBuilding: { type: String },
        street: { type: String },
        latitude: { type: Number },
        longitude: { type: Number }
    },
    // END: NEW Structured Location
    scheduledDateTime: { type: Date, required: true },
    notes: String,
    status: { type: String, default: 'Pending', enum: ['Pending', 'Accepted', 'In Progress', 'Diagnosed', 'Quotation Approved', 'Paid', 'Completed', 'Cancelled'] },
    assignedTechnicianId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    assignedTechnicianName: String,
    faultyParts: [String],
    technicianRemarks: String,
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
        details: Object,
        status: { type: String, enum: ['Pending', 'Paid', 'Failed', 'Refunded'], default: 'Pending' },
        paidAt: Date,
        transactionId: { type: String, unique: true, sparse: true }
    },
    completedAt: Date,
    rating: { type: Number, min: 1, max: 5 },
    reviewText: String,
    reviewedAt: Date,
    proofImages: [String],
    technicianProposals: [{
        technicianId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        priceQuote: { type: Number },
        proposedAt: { type: Date }
    }],
    // ADD THESE TWO NEW FIELDS
    isWarrantyClaim: { type: Boolean, default: false }, // Flag to identify warranty claims
    originalJobId: { type: String } // Reference to the job being claimed against
}, { timestamps: true });

jobSchema.pre('save', async function(next) {
    if (this.isNew && !this.jobId) {
        const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, ''); //YYYYMMDD
        const randomPart = crypto.randomBytes(3).toString('hex').toUpperCase(); // 6 random hex chars
        this.jobId = `TSJ-${datePart}-${randomPart}`; // Generate unique Job ID
    }
    next();
});

const Job = mongoose.model('Job', jobSchema);


// Ticket Schema (for complaints and support queries)
const ticketSchema = new mongoose.Schema({
    ticketId: { type: String, unique: true, required: true },
    raisedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // User, Technician, or Admin
    subject: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['Open', 'In Progress', 'Resolved', 'Closed', 'Escalated'], default: 'Open' },
    priority: { type: String, enum: ['Low', 'Medium', 'High', 'Urgent'], default: 'Medium' },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Assigned admin/support agent
    lastUpdate: { type: Date, default: Date.now },
    serviceType: { type: String }, // Optional, for service admin context (e.g., AC Repair)
    escalationReason: { type: String }, // If escalated, why
    messages: [{ // Chat history within the ticket
        sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        message: { type: String },
        timestamp: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

// Removed the pre-save hook for ticketId as it will now be generated before creating the document
// ticketSchema.pre('save', async function(next) {
//     if (this.isNew && !this.ticketId) {
//         const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
//         const randomPart = crypto.randomBytes(2).toString('hex').toUpperCase();
//         this.ticketId = `TST-${datePart}-${randomPart}`;
//     }
//     next();
// });

const Ticket = mongoose.model('Ticket', ticketSchema);


// Promotion Schema (for coupons and discounts)
const promotionSchema = new mongoose.Schema({
    couponCode: { type: String, required: true, unique: true, uppercase: true },
    discountType: { type: String, enum: ['percentage', 'fixed'], required: true },
    discountValue: { type: Number, required: true, min: 0 },
    minOrderAmount: { type: Number, default: 0, min: 0 },
    maxDiscount: { type: Number, min: 0 }, // For percentage discounts, to cap the max discount amount
    expiryDate: { type: Date, required: true },
    targetAudience: [{ type: String }], // e.g., 'All', 'Customers', 'Technician', 'Delhi', 'Plumbing'
    usageLimit: { type: Number, default: 1, min: 1 }, // Usage limit per user
    totalUsageLimit: { type: Number, min: 1 }, // Overall usage limit for the coupon
    usageCount: { type: Number, default: 0 }, // How many times it has been used
    status: { type: String, enum: ['Active', 'Inactive', 'Pending', 'Approved', 'Rejected'], default: 'Pending' }, // For admin approval flow
    suggestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // If suggested by a City/Service Admin
    suggestedCities: [{ type: String }], // If suggested by Citymanager
    targetServices: [{ type: String }] // If suggested by Serviceadmin
}, { timestamps: true });
const Promotion = mongoose.model('Promotion', promotionSchema);


// Announcement Schema (in-app notifications)
const announcementSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    targetAudience: [{ type: String }], // e.g., ['All', 'Customers', 'Technician', 'Citymanager']
    publishedOn: { type: Date, default: Date.now },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Admin who created it
}, { timestamps: true });
const Announcement = mongoose.model('Announcement', announcementSchema);


// Contact Message Schema (from public contact form)
const contactMessageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true }
}, { timestamps: true });
const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);


// Fee Recommendation Schema (from Serviceadmin to Superadmin/Financeofficer)
const feeRecommendationSchema = new mongoose.Schema({
    serviceType: { type: String, required: true }, // e.g., 'AC Repair'
    feeType: { type: String, enum: ['basePrice', 'commissionRate', 'laborCost'], required: true },
    currentValue: { type: Number, required: true },
    newProposedValue: { type: Number, required: true },
    reason: { type: String, required: true },
    recommendedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    adminRole: { type: String, required: true }, // e.g., 'Serviceadmin'
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' }
}, { timestamps: true });
const FeeRecommendation = mongoose.model('FeeRecommendation', feeRecommendationSchema);


// Financial Log Schema (for audit trail of financial events)
const financialLogSchema = new mongoose.Schema({
    logId: { type: String, unique: true, required: true },
    eventType: { type: String, required: true }, // e.g., 'Transaction Processed', 'Payout Initiated', 'Refund Issued', 'Configuration Change'
    relatedId: { type: String }, // e.g., jobId, transactionId, userId, couponId
    description: { type: String, required: true },
    amount: { type: Number }, // Relevant for financial events
    flaggedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reasonFlagged: { type: String },
    status: { type: String, enum: ['Normal', 'Flagged', 'Resolved Flag'], default: 'Normal' }, // Audit status
    timestamp: { type: Date, default: Date.now }
}, { timestamps: true });

financialLogSchema.pre('save', async function(next) {
    if (this.isNew && !this.logId) {
        const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const randomPart = crypto.randomBytes(2).toString('hex').toUpperCase();
        this.logId = `TSL-${datePart}-${randomPart}`;
    }
    next();
});

const FinancialLog = mongoose.model('FinancialLog', financialLogSchema);


// Transaction Schema (for explicit financial movements within the system)
const transactionSchema = new mongoose.Schema({
    transactionId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Initiator of transaction or primary user involved
    relatedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Other party (e.g., technician for customer payment)
    jobId: { type: String, sparse: true }, // Optional, if related to a job
    type: { type: String, enum: ['PaymentIn', 'Payout', 'Commission', 'Refund', 'FeeChange', 'Earning'], required: true }, // E.g., 'PaymentIn' for customer, 'Payout' for technician, 'Commission' for app
    amount: { type: Number, required: true },
    status: { type: String, enum: ['Success', 'Failed', 'Pending'], default: 'Pending' },
    paymentMethod: { type: String }, // e.g., 'UPI', 'NetBanking', 'Card', 'Cash'
    description: { type: String } // Detailed description of the transaction
}, { timestamps: true });

transactionSchema.pre('save', async function(next) {
    if (this.isNew && !this.transactionId) {
        const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const randomPart = crypto.randomBytes(3).toString('hex').toUpperCase();
        this.transactionId = `TSTXN-${datePart}-${randomPart}`;
    }
    next();
});

const Transaction = mongoose.model('Transaction', transactionSchema);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
// --- Core Express Middleware ---
// app.use(express.json()); 
// app.use(express.urlencoded({ extended: true })); 
app.set('trust proxy', 1); // Required if your app is behind a proxy (like Render)

// CORS configuration to allow requests from the frontend
app.use(cors({
    origin: process.env.FRONTEND_URL || '*', 
    credentials: true
}));

// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: 'sessions',
        ttl: 24 * 60 * 60, // 1 day
        autoRemove: 'interval',
        autoRemoveInterval: 10 // In minutes
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true, // Prevents client-side JS from reading the cookie
        sameSite: 'lax', // Protects against CSRF
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Nodemailer transporter setup for sending emails (e.g., OTPs)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
    },
});

const otpStore = {}; // In-memory OTP store (not for production with multiple instances)

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendEmailOTP(email, otp, subject = 'Your TechSeva OTP', body = `Your One-Time Password (OTP) for TechSeva is: <strong>${otp}</strong><p>This OTP is valid for 5 minutes.</p>`) {
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
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.id) {
        next();
    } else {
        if (req.accepts('html')) {
            console.log(`Unauthenticated HTML request for ${req.path}, redirecting to /`);
            res.redirect('/');
        } else {
            console.log(`Unauthenticated API request for ${req.path}, sending 401 JSON response.`);
            res.status(401).json({ success: false, message: 'Unauthorized. Please login.', redirect: '/' });
        }
    }
}

// Middleware to check role for admin access
const isAdmin = async (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    console.warn(`Access denied to ${req.path}: Not an administrator. User role: ${req.session.user ? req.session.user.role : 'none'}`);
    res.status(403).json({ success: false, message: 'Access denied: Not an administrator.' });
};

// Middleware to check role for technician access
const isTechnician = async (req, res, next) => {
    if (req.session.user && req.session.user.role === 'technician') {
        return next();
    }
    console.warn(`Access denied to ${req.path}: Not a technician. User role: ${req.session.user ? req.session.user.role : 'none'}`);
    res.status(403).json({ success: false, message: 'Access denied: Not a technician.' });
};

// Middleware to check role for user access
const isUser = async (req, res, next) => {
    if (req.session.user && req.session.user.role === 'user') {
        return next();
    }
    console.warn(`Access denied to ${req.path}: Not a user. User role: ${req.session.user ? req.session.user.role : 'none'}`);
    res.status(403).json({ success: false, message: 'Access denied: Not a user.' });
};

// Multer setup for handling file uploads (e.g., proof images in diagnosis, KYC docs)
const upload = multer({ storage: multer.memoryStorage() }); // Use memory storage for base64 conversion later

// --- Custom Authentication & Authorization Middleware ---

// Middleware to check if user is authenticated (session exists)
function authenticateToken(req, res, next) {
    if (req.session.user && req.session.user.id) {
        next();
    } else {
        if (req.accepts('html')) {
            console.log(`Unauthenticated HTML request for ${req.path}, redirecting to /`);
            res.redirect('/');
        } else {
            console.log(`Unauthenticated API request for ${req.path}, sending 401 JSON response.`);
            res.status(401).json({ success: false, message: 'Unauthorized. Please login.', redirect: '/' });
        }
    }
}

// Middleware to load current user details into req.user for easier access
// This should be applied after session middleware and authentication check
async function loadUser(req, res, next) {
    if (req.session && req.session.user && req.session.user.id) {
        try {
            // Fetch user from DB using session ID, exclude password
            req.user = await User.findById(req.session.user.id).select('-password').lean(); 
            if (!req.user) {
                // User not found in DB, destroy session to force re-login
                req.session.destroy(err => {
                    if (err) console.error('Session destruction error on user not found in DB:', err);
                    return res.status(401).json({ success: false, message: 'User data not found. Session cleared. Please log in again.', redirect: '/' });
                });
                return; // Stop further execution
            }
            // Ensure req.user has a populated role for authorizeRoles to work correctly
            if (!req.user.role) {
                console.warn(`[LOAD USER] User ${req.user._id} found, but role is missing. Defaulting to 'user'.`);
                req.user.role = 'user'; // Default or handle appropriately
            }
            next(); // User loaded, proceed
        } catch (error) {
            console.error('Error loading user details into req.user:', error);
            // In case of a DB error during load, destroy session
            req.session.destroy(err => {
                if (err) console.error('Session destruction error during user load error:', err);
                return res.status(500).json({ success: false, message: 'Server error loading user data. Please try again.' });
            });
            return; // Stop further execution
        }
    } else {
        next(); // No authenticated user in session, req.user remains undefined, continue to allow public routes
    }
}
app.use(loadUser); // Apply globally to populate req.user for all subsequent routes

// Middleware to authorize roles dynamically
function authorizeRoles(roles) {
    return (req, res, next) => {
        // req.user should be populated by loadUser middleware
        if (!req.user) {
            console.warn(`[AUTHORIZE ROLE] No user in req.user for path: ${req.path}. Authentication required first.`);
            return res.status(401).json({ success: false, message: 'Authentication required for this resource.' });
        }
        
        console.log(`[AUTHORIZE ROLE] User ${req.user.email} (Role: ${req.user.role}) attempting to access path: ${req.path}. Required roles: ${roles.join(', ')}`);

        if (roles.includes(req.user.role)) {
            return next(); // User has one of the required roles
        }
        
        // Special handling for Superadmin: Superadmin can access all admin-level roles' endpoints
        // This logic is already present and correct.
        if (req.user.role === 'Superadmin' && roles.some(role => ['Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent'].includes(role))) {
            console.log(`[AUTHORIZE ROLE] Superadmin ${req.user.email} granted access to admin-level resource.`);
            return next();
        }

        console.warn(`[AUTHORIZE ROLE] Access denied for ${req.user.email} (Role: ${req.user.role}) to path: ${req.path}. Insufficient permissions.`);
        res.status(403).json({ success: false, message: `Access denied. You do not have the required permissions for this action. Your role: ${req.user.role}` });
    };
}


// Helper to check if a role is one of the specific admin roles (used in login/register logic)
const isAnAdminRole = (role) => {
    return ['Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent'].includes(role);
};


// --- HTML Page Routes (Serve Frontend Views) ---

// Serve the main index.html file as the homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Serve signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

// Serve forgot password page
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'forgot-password.html'));
});

// Serve phone update page
app.get('/phone-update', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'phone-update.html'));
});

// Serve static files from 'public'
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // For serving uploaded images

// Serve other general HTML pages
app.get('/working.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'working.html'));
});

app.get('/contact.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'contact.html'));
});

// Admin login page route (public, no auth required)
app.get('/admin-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin_login.html'));
});

// Protected HTML routes (render specific dashboards based on role)
app.get('/user', authenticateToken, authorizeRoles(['user']), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

app.get('/technician', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    // Additionally check KYC status for technicians accessing their dashboard
    // req.user is already populated by loadUser
    if (!req.user || req.user.kycStatus !== 'approved') {
        console.warn(`Technician ${req.user ? req.user._id : 'N/A'} attempted to access dashboard with KYC status: ${req.user ? req.user.kycStatus : 'not found'}. Redirecting.`);
        req.session.destroy(() => { res.redirect('/'); });
        return;
    }
    res.sendFile(path.join(__dirname, 'views', 'technician.html'));
});

app.get('/payment', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'payment.html'));
});

app.get('/diagnosis', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'diagnosis.html'));
});

// Specific admin dashboard routes
app.get('/superadmin', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'superadmin.html'));
});

app.get('/citymanager', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'citymanager.html'));
});

app.get('/serviceadmin', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'serviceadmin.html'));
});

app.get('/financeofficer', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'financeofficer.html'));
});

app.get('/supportagent', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'supportagent.html'));
});


// --- User Authentication API Routes (Public) ---

// Send OTP for signup or password reset
app.post('/send-otp', async (req, res) => {
    console.log('[SEND OTP] Request received for email:', req.body.email);
    try {
        const { email, type = 'signup' } = req.body; // 'signup' or 'password_reset'
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required to send OTP.' });
        }

        const user = await User.findOne({ email });

        if (type === 'signup') {
            if (user && user.isVerified) {
                console.warn('[SEND OTP] User already exists and is verified:', email);
                return res.status(409).json({ success: false, message: 'User with this email already exists and is verified. Please login.' });
            }
        } else if (type === 'password_reset') {
            if (!user) {
                console.warn('[SEND OTP] Password reset requested for non-existent user:', email);
                // Still return success to prevent email enumeration
                return res.json({ success: true, message: 'If this email is registered, a password reset OTP has been sent.' });
            }
            if (!user.password && user.googleId) {
                console.warn(`[SEND OTP] Account ${email} is Google registered, password reset not applicable.`);
                return res.status(400).json({ success: false, message: 'This account is registered via Google. Password reset is not applicable.' });
            }
        }

        const otp = generateOTP();
        otpStore[email] = { otp, expiresAt: Date.now() + 300000, type: type }; // 5 minutes validity
        console.log(`[SEND OTP] Generated OTP for ${email} (type: ${type}): ${otp}`);

        const emailSubject = type === 'signup' ? 'Your TechSeva OTP for Registration' : 'Your TechSeva Password Reset OTP';
        const emailBody = `<p>Your One-Time Password (OTP) for TechSeva is: <strong>${otp}</strong><p>This OTP is valid for 5 minutes.</p>`;

        const sent = await sendEmailOTP(email, otp, emailSubject, emailBody);
        if (sent) {
            return res.json({ success: true, message: `OTP sent to ${email}. Please check your email.` });
        } else {
            console.error('[SEND OTP] Failed to send OTP email via Nodemailer.');
            return res.status(500).json({ success: false, message: 'Failed to send OTP email. Please check server logs and Nodemailer configuration.' });
        }
    } catch (err) {
        console.error('[SEND OTP ERROR]:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP sending.' });
    }
});

// Verify OTP for signup
app.post('/verify-otp', (req, res) => {
    console.log('[VERIFY OTP] Request received for email:', req.body.email);
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email and OTP are required for verification.' });
        }
        const storedOtpData = otpStore[email];
        if (!storedOtpData || storedOtpData.type !== 'signup') {
            console.warn('[VERIFY OTP] No valid signup OTP found for email:', email);
            return res.status(400).json({ success: false, message: 'No valid OTP found for this email or it is not a signup OTP.' });
        }
        if (Date.now() > storedOtpData.expiresAt) {
            delete otpStore[email];
            console.warn('[VERIFY OTP] OTP expired for email:', email);
            return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
        }
        if (storedOtpData.otp !== otp) {
            delete otpStore[email]; // Invalidate OTP on wrong attempt
            console.warn('[VERIFY OTP] Invalid OTP provided for email:', email);
            return res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
        }
        delete otpStore[email]; // OTP consumed
        console.log('[VERIFY OTP] OTP verified successfully for email:', email);
        return res.json({ success: true, message: 'OTP verified successfully.' });
    } catch (err) {
        console.error('[VERIFY OTP ERROR]:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during OTP verification for signup.' });
    }
});

// User Registration
app.post('/register', async (req, res) => {
    console.log('[REGISTER] Request received for:', req.body.email, 'Role:', req.body.role);
    try {
        const { fullName, email, password, role, aadhaar, pan, skills } = req.body;
        // Ensure phoneNumber is undefined if empty or not provided
        const phoneNumber = req.body.phoneNumber ? req.body.phoneNumber.trim() : undefined;

        if (!fullName || !email || !password || !role) { 
            console.warn('[REGISTER] Missing required fields for registration.');
            return res.status(400).json({ success: false, message: 'All required fields must be provided.' });
        }

        // Prevent registration of any admin role via this route
        if (isAnAdminRole(role)) {
            console.warn(`[REGISTER] Attempt to register admin role (${role}) via regular route.`);
            return res.status(403).json({ success: false, message: 'Admin accounts cannot be created via user registration.' });
        }

        // Check for existing user by email
        let existingUserByEmail = await User.findOne({ email });
        if (existingUserByEmail) {
            if (!existingUserByEmail.isVerified) {
                // If user exists but isn't verified, update their details and mark as verified
                console.log(`[REGISTER] User ${email} found but not verified. Updating details.`);
                existingUserByEmail.fullName = fullName;
                existingUserByEmail.phoneNumber = phoneNumber; // Use processed phoneNumber
                existingUserByEmail.password = password; // Hashed by pre-save hook
                existingUserByEmail.role = role;
                existingUserByEmail.isVerified = true;
                if (role === 'technician') {
                    existingUserByEmail.aadhaar = aadhaar;
                    existingUserByEmail.pan = pan;
                    existingUserByEmail.bankDetails = {}; 
                    existingUserByEmail.skills = skills ? skills.split(',').map(s => s.trim()) : [];
                    existingUserByEmail.kycStatus = 'pending';
                    existingUserByEmail.balance = existingUserByEmail.balance || 0;
                } else { // user role
                    existingUserByEmail.aadhaar = undefined; existingUserByEmail.pan = undefined;
                    existingUserByEmail.bankDetails = undefined; existingUserByEmail.skills = undefined;
                    existingUserByEmail.kycStatus = 'approved';
                }
                await existingUserByEmail.save();
                
                req.session.user = {
                    id: existingUserByEmail._id.toString(),
                    fullName: existingUserByEmail.fullName,
                    email: existingUserByEmail.email,
                    role: existingUserByEmail.role,
                    kycStatus: existingUserByEmail.kycStatus
                };
                let redirectUrl = '/';
                if (existingUserByEmail.role === 'technician') redirectUrl = '/technician';
                else if (existingUserByEmail.role === 'user') redirectUrl = '/user'; // Default for user
                
                console.log(`[REGISTER] User ${email} account updated and verified. Redirecting to ${redirectUrl}`);
                return res.json({ success: true, message: `Welcome back! Account updated and verified.`, redirect: redirectUrl });

            } else {
                console.warn(`[REGISTER] User with email ${email} already exists and is verified.`);
                return res.status(409).json({ success: false, message: 'User with this email already exists and is verified. Please login.' });
            }
        }

        // Check for existing user by phone number (only if phoneNumber is provided)
        if (phoneNumber) {
            const existingUserByPhone = await User.findOne({ phoneNumber });
            if (existingUserByPhone) {
                console.warn(`[REGISTER] User with phone number ${phoneNumber} already exists.`);
                return res.status(409).json({ success: false, message: 'User with this phone number already exists. Please login or use a different phone number.' });
            }
        }
       
        const newUser = new User({
            fullName,
            email,
            phoneNumber, // Use the processed phoneNumber (will be undefined if empty)
            password: password, // Pre-save hook will hash this
            role,
            isVerified: true, // Marking as verified since OTP flow is assumed complete
        });

        if (role === 'technician') {
            if (!aadhaar || !pan || !skills) {
                console.warn('[REGISTER] Technician registration missing Aadhaar, PAN, or Skills.');
                return res.status(400).json({ success: false, message: 'Technician registration requires Aadhaar, PAN, and Skills.' });
            }
            newUser.aadhaar = aadhaar;
            newUser.pan = pan;
            newUser.bankDetails = {}; 
            newUser.skills = skills.split(',').map(s => s.trim());
            newUser.kycStatus = 'pending';
            newUser.balance = 0;
        } else { // 'user' role
            newUser.kycStatus = 'approved';
        }

        console.log("[REGISTER] Attempting to save new user:", newUser.email);
        await newUser.save();
        console.log("[REGISTER] New user registered successfully:", newUser._id);

        req.session.user = {
            id: newUser._id.toString(),
            fullName: newUser.fullName,
            email: newUser.email,
            role: newUser.role,
            kycStatus: newUser.kycStatus
        };

        let redirectUrl;
        // Updated redirect logic for all roles including new admin ones
        switch (newUser.role) {
            case 'user':
                redirectUrl = '/user';
                break;
            case 'technician':
                redirectUrl = '/technician';
                break;
            case 'Superadmin':
                redirectUrl = '/superadmin';
                break;
            case 'Citymanager':
                redirectUrl = '/citymanager';
                break;
            case 'Serviceadmin':
                redirectUrl = '/serviceadmin';
                break;
            case 'Financeofficer':
                redirectUrl = '/financeofficer';
                break;
            case 'Supportagent':
                redirectUrl = '/supportagent';
                break;
            default:
                redirectUrl = '/'; // Fallback
                break;
        }

        console.log(`[REGISTER] User ${newUser.email} (${newUser.role}) logged in. Redirecting to ${redirectUrl}`);
        return res.json({
            success: true,
            message: `Registration successful for ${role}. You are now logged in.`,
            redirect: redirectUrl,
            user: req.session.user
        });

    } catch (err) {
        console.error('[REGISTER ERROR]:', err);
        if (err.code === 11000) { // MongoDB duplicate key error
            let field = Object.keys(err.keyValue)[0];
            // Provide more specific message if it's the phoneNumber duplicate
            if (field === 'phoneNumber') {
                return res.status(409).json({ success: false, message: 'A user with this phone number already exists. Please login or use a different phone number.' });
            }
            return res.status(409).json({ success: false, message: `A user with this ${field} already exists.` });
        }
        res.status(500).json({ success: false, message: 'Internal server error during registration.' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    console.log('[LOGIN] Received login request body for email:', req.body.email, ' and selected role:', req.body.role);
    try {
        const { email, password, role: selectedRoleFromFrontend } = req.body; 

        if (!email || !password || !selectedRoleFromFrontend) {
            return res.status(400).json({ success: false, message: 'Email, password, and role are required for login.' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            console.warn('[LOGIN] Invalid credentials: User not found for email:', email);
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }
        
        // Directly compare the selected role with the role stored in the database
        if (user.role !== selectedRoleFromFrontend) {
            console.warn(`[LOGIN] Access denied: User ${email} is registered as ${user.role}, but attempted to log in as ${selectedRoleFromFrontend}.`);
            return res.status(403).json({ success: false, message: `You are registered as a ${user.role}. Please select the correct role.` });
        }

        if (!user.password && user.googleId) {
            console.warn(`[LOGIN] User ${email} attempted password login but is Google registered.`);
            return res.status(401).json({ success: false, message: 'This account is registered via Google. Please use "Sign in with Google" button.' });
        }

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            console.warn(`[LOGIN] Invalid password for user: ${email}`);
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        if (user.role === 'technician' && user.kycStatus !== 'approved') {
            let message = `Your technician application is currently ${user.kycStatus}.`;
            if (user.kycStatus === 'pending') {
                message += ' Please wait for approval to access technician features.';
            } else if (user.kycStatus === 'rejected') {
                message += ' Please contact support for more information.';
            }
            console.warn(`[LOGIN] Technician ${email} KYC status is ${user.kycStatus}.`);
            return res.status(403).json({ success: false, message: message });
        }

        req.session.user = {
            id: user._id.toString(),
            fullName: user.fullName,
            email: user.email,
            role: user.role, // Store the actual specific role from DB
            kycStatus: user.kycStatus
        };

        let redirectUrl;
        // Corrected redirect logic for all roles including new admin ones
        switch (user.role) {
            case 'user':
                redirectUrl = '/user';
                break;
            case 'technician':
                redirectUrl = '/technician';
                break;
            case 'Superadmin':
                redirectUrl = '/superadmin';
                break;
            case 'Citymanager':
                redirectUrl = '/citymanager';
                break;
            case 'Serviceadmin':
                redirectUrl = '/serviceadmin';
                break;
            case 'Financeofficer':
                redirectUrl = '/financeofficer';
                break;
            case 'Supportagent':
                redirectUrl = '/supportagent';
                break;
            default:
                redirectUrl = '/'; // Fallback
                break;
        }

        console.log(`[LOGIN] User ${user.email} (${user.role}) logged in successfully. Redirecting to ${redirectUrl}`);
        return res.json({
            success: true,
            message: 'Login successful',
            redirect: redirectUrl,
            user: req.session.user
        });

    } catch (err) {
        console.error('[LOGIN ERROR]:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during login.' });
    }
});
// Google Login
app.post('/api/google-login', async (req, res) => {
    console.log('[GOOGLE LOGIN] Request received with ID token.');
    const { idToken } = req.body;

    if (!idToken) {
        console.warn('[GOOGLE LOGIN] Google ID token is missing.');
        return res.status(400).json({ success: false, message: 'Google ID token is required.' });
    }
    if (!googleAuthClient) {
        console.error('[GOOGLE LOGIN] Server-side Google OAuth client not initialized. Missing GOOGLE_CLIENT_ID.');
        return res.status(500).json({ success: false, message: 'Server-side Google OAuth client not initialized. Missing GOGLE_CLIENT_ID.' });
    }

    try {
        const ticket = await googleAuthClient.verifyIdToken({
            idToken: idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { sub: googleId, email, name: fullName, email_verified } = payload;
        console.log('[GOOGLE LOGIN] Token verified. Payload:', { email, fullName, googleId });

        if (!email_verified) {
            console.warn('[GOOGLE LOGIN] Google account email not verified:', email);
            return res.status(400).json({ success: false, message: 'Google account email not verified.' });
        }
        // MODIFIED: Search for existing user by BOTH googleId and email.
        let user = await User.findOne({ $or: [{ googleId: googleId }, { email: email }] });
        if (user) {
            console.log('[GOOGLE LOGIN] Existing user found:', user.email);
            // Ensure both googleId and email are correctly linked to the existing user
            if (!user.googleId) {
                user.googleId = googleId;
                await user.save();
                console.log('[GOOGLE LOGIN] Added Google ID to existing user:', user.email);
            }
            if (user.email !== email) {
                console.warn('[GOOGLE LOGIN] Mismatch between Google email and stored email for user:', user.email, ' and ', email);
            }
            
            // Ensure role is 'user' if it's not technician/admin (don't downgrade existing roles)
            if (!isAnAdminRole(user.role) && user.role !== 'technician') {
                user.role = 'user'; // Default to user if not technician or a specific admin role
                user.kycStatus = 'approved'; // Google users are implicitly KYC approved for user role
                await user.save();
            }

            if (user.role === 'technician' && user.kycStatus !== 'approved') {
                let message = `Your technician application is currently ${user.kycStatus}.`;
                if (user.kycStatus === 'pending') {
                    message += ' Please wait for approval to access technician features.';
                } else if (user.kycStatus === 'rejected') {
                    message += ' Please contact support for more information.';
                }
                console.warn(`[GOOGLE LOGIN] Technician ${user.email} KYC status is ${user.kycStatus}.`);
                return res.status(403).json({ success: false, message: message });
            }

            req.session.user = {
                id: user._id.toString(),
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                kycStatus: user.kycStatus,
                phoneNumber: user.phoneNumber
            };

            if (!user.phoneNumber) {
                console.log(`[GOOGLE LOGIN] Existing user ${user.email} has no phone number. Prompting for update.`);
                return res.json({ success: true, message: 'Please provide a phone number to continue.', needsPhoneUpdate: true });
            }

            let redirectUrl = '/user'; // Default redirect
            switch (user.role) {
                case 'technician':
                    redirectUrl = '/technician';
                    break;
                case 'Superadmin':
                    redirectUrl = '/superadmin';
                    break;
                case 'Citymanager':
                    redirectUrl = '/citymanager';
                    break;
                case 'Serviceadmin':
                    redirectUrl = '/serviceadmin';
                    break;
                case 'Financeofficer':
                    redirectUrl = '/financeofficer';
                    break;
                case 'Supportagent':
                    redirectUrl = '/supportagent';
                    break;
            }

            console.log(`[GOOGLE LOGIN] Logged in existing user ${user.email}. Redirecting to ${redirectUrl}`);
            return res.json({ success: true, message: 'Logged in with Google successfully!', redirect: redirectUrl });

        } else {
            console.log('[GOOGLE LOGIN] No existing user found. Creating new user with Google ID.');
            const newUser = new User({
                fullName: fullName || 'Google User',
                email: email,
                googleId: googleId,
                role: 'user', // Default role for new Google sign-ups
                isVerified: true,
                kycStatus: 'approved' // New Google sign-ups are considered KYC approved for user role
            });
            await newUser.save();
            console.log('[GOOGLE LOGIN] New Google user created:', newUser.email);

            req.session.user = {
                id: newUser._id.toString(),
                fullName: newUser.fullName,
                email: newUser.email,
                role: newUser.role,
                kycStatus: newUser.kycStatus
            };
            return res.json({ success: true, message: 'Please add your phone number to complete your profile.', needsPhoneUpdate: true });
        }

    } catch (error) {
        console.error('[GOOGLE LOGIN ERROR] Google ID token verification failed:', error);
        res.status(401).json({ success: false, message: 'Google Sign-in failed. Please try again.' });
    }
});

// Reset password
app.post('/reset-password', async (req, res) => {
    console.log('[RESET PASSWORD] Request received for email:', req.body.email);
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    if (newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'New password must be at least 8 characters long.' });
    }

    const storedOtpData = otpStore[email];

    if (!storedOtpData || storedOtpData.otp !== otp || Date.now() > storedOtpData.expiresAt || storedOtpData.type !== 'password_reset') {
        console.warn('[RESET PASSWORD] Invalid or expired OTP provided for email:', email);
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.warn('[RESET PASSWORD] User not found for password reset:', email);
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        if (!user.password && user.googleId) {
            console.warn(`[RESET PASSWORD] Account ${email} is Google registered, password reset not applicable.`);
            return res.status(400).json({ success: false, message: 'This account is registered via Google. Password reset is not applicable.' });
        }

        user.password = newPassword; // Pre-save hook will hash this
        await user.save();
        console.log('[RESET PASSWORD] Password updated successfully for user:', email);

        delete otpStore[email]; // Consume OTP

        res.json({ success: true, message: 'Your password has been reset successfully. You can now log in with your new password.' });

    } catch (error) {
        console.error('[RESET PASSWORD ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error during password reset.' });
    }
});

// User logout
app.post('/logout', (req, res) => {
    console.log('[LOGOUT] Request received. Attempting to destroy session.');
    req.session.destroy(err => {
        if (err) {
            console.error('[LOGOUT ERROR]: Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Could not log out. Please try again.' });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        console.log('[LOGOUT] Session destroyed and cookie cleared. User logged out.');
        res.json({ success: true, message: 'Logged out successfully.', redirect: '/' });
    });
});


// --- User (Customer) Specific API Endpoints ---

// Get current user details
app.get('/api/user/me', authenticateToken, authorizeRoles(['user', 'technician', 'Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
    // req.user is already populated by loadUser middleware
    if (!req.user) {
        return res.status(404).json({ success: false, message: 'User data not found in session.' });
    }
    // Password is already excluded by loadUser's select('-password')
    res.json({ success: true, user: req.user });
});

// Update user profile
app.post('/api/user/profile/update', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log(`[PROFILE UPDATE] Received update request for user ${req.user._id}. Data:`, req.body);
    try {
        const userId = req.user._id;
        // UPDATED: Now expecting a single 'address' object from the frontend
        const { fullName, phoneNumber: rawPhoneNumber, address } = req.body;
        const phoneNumber = rawPhoneNumber ? rawPhoneNumber.trim() : undefined; // Process phoneNumber

        const user = await User.findById(userId);
        if (!user) {
            console.warn(`[PROFILE UPDATE] User ${userId} not found in DB.`);
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Handle Phone Number Uniqueness Check
        if (phoneNumber !== undefined && phoneNumber !== user.phoneNumber) {
            const existingUserWithPhone = await User.findOne({ phoneNumber: phoneNumber, _id: { $ne: userId } });
            if (existingUserWithPhone) {
                console.warn(`[PROFILE UPDATE] Phone number ${phoneNumber} is already taken by another user.`);
                return res.status(409).json({ success: false, message: 'This phone number is already registered with another account.' });
            }
            user.phoneNumber = phoneNumber;
        } else if (phoneNumber === undefined && user.phoneNumber) {
            user.phoneNumber = undefined;
        }


        if (fullName !== undefined) user.fullName = fullName;
        
        // NEW: Directly set the new structured address object
        if (address !== undefined) {
             user.address = address;
        }
        
        await user.save();
        console.log(`[PROFILE UPDATE] User ${userId} profile updated successfully.`);

        // UPDATED: Update session user data to reflect the new address object
        req.session.user.fullName = user.fullName;
        req.session.user.phoneNumber = user.phoneNumber;
        req.session.user.address = user.address;

        const updatedUser = await User.findById(userId).select('-password').lean();

        res.json({ success: true, message: 'Profile updated successfully!', user: updatedUser });

    } catch (err) {
        console.error('[PROFILE UPDATE ERROR]:', err);
        if (err.code === 11000) { 
            let field = Object.keys(err.keyValue)[0];
            return res.status(409).json({ success: false, message: `A user with this ${field} already exists.` });
        }
        res.status(500).json({ success: false, message: 'Internal server error during profile update.' });
    }
});
// Add this new route after your existing user-related API endpoints.
// NEW API Endpoint for profile photo upload
app.post('/api/user/profile/upload-photo', authenticateToken, authorizeRoles(['user', 'technician', 'Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
  try {
    const { photoData } = req.body;
    const userId = req.user._id;

    if (!photoData || !userId) {
      return res.status(400).json({ success: false, message: 'Missing photo data or user ID.' });
    }

    // Now, we save the Base64 string directly to the database.
    const newProfilePicture = photoData;

    // Find the user in the database and update their profile picture
    const updatedUser = await User.findOneAndUpdate(
      { _id: userId },
      { profilePictureUrl: newProfilePicture }, // FIX: Corrected field name to match schema
      { new: true, runValidators: true }
    ).lean();

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    console.log('Profile photo updated for user:', userId);

    // Respond with a success message and the new user object containing the updated URL
    res.json({ success: true, message: 'Profile photo uploaded successfully!', user: updatedUser });

  } catch (error) {
    console.error('Error during photo upload:', error);
    res.status(500).json({ success: false, message: 'Failed to upload photo.' });
  }
});

// NEW API Endpoint for updating phone number (used after Google login)
app.post('/api/user/update-phone', authenticateToken, authorizeRoles(['user', 'technician', 'Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
  console.log('[UPDATE PHONE API] Request received for user:', req.user._id);
  try {
    const { phoneNumber } = req.body;
    const userId = req.user._id;

    if (!phoneNumber || !/^\d{10}$/.test(phoneNumber.trim())) {
      return res.status(400).json({ success: false, message: 'Please provide a valid 10-digit phone number.' });
    }

    const trimmedPhone = phoneNumber.trim();

    // Check for uniqueness
    const existingUserWithPhone = await User.findOne({ phoneNumber: trimmedPhone, _id: { $ne: userId } });
    if (existingUserWithPhone) {
      console.warn('[UPDATE PHONE API] Phone number already taken:', trimmedPhone);
      return res.status(409).json({ success: false, message: 'This phone number is already registered with another account.' });
    }

    // Update the user's phone number
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { phoneNumber: trimmedPhone },
      { new: true, runValidators: true }
    ).select('-password').lean();

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    // Update session
    req.session.user.phoneNumber = trimmedPhone;

    console.log('[UPDATE PHONE API] Phone number updated for user:', userId);

    // Determine redirect URL based on role
    let redirectUrl = '/user'; // Default
    switch (updatedUser.role) {
      case 'technician':
        redirectUrl = '/technician';
        break;
      case 'Superadmin':
        redirectUrl = '/superadmin';
        break;
      case 'Citymanager':
        redirectUrl = '/citymanager';
        break;
      case 'Serviceadmin':
        redirectUrl = '/serviceadmin';
        break;
      case 'Financeofficer':
        redirectUrl = '/financeofficer';
        break;
      case 'Supportagent':
        redirectUrl = '/supportagent';
        break;
    }

    res.json({
      success: true,
      message: 'Phone number updated successfully! Welcome to TechSeva.',
      redirect: redirectUrl,
      user: updatedUser
    });

  } catch (error) {
    console.error('[UPDATE PHONE API ERROR]:', error);
    res.status(500).json({ success: false, message: 'Internal server error during phone update.' });
  }
});


// Book a service (User)

// Book a service (User)
// Book a service (User)
// Book a service (User)
app.post('/api/book-service', isAuthenticated, isUser, async (req, res) => {
    console.log('[BOOK SERVICE API] Received booking request:', req.body, 'by user:', req.session.user.id);
    try {
        // UPDATED: Now expecting a single 'location' object from the frontend, with lat/lon inside it.
        const { applianceType, location, scheduledDateTime, notes, isWarrantyClaim, originalJobId } = req.body; 
        const userId = req.session.user.id;

        // UPDATED: Check for all required location sub-fields.
        if (!applianceType || !location || !location.pincode || !location.state || !location.city || !location.houseBuilding || !location.street || !scheduledDateTime) {
            console.warn('[BOOK SERVICE API] Missing required fields for booking:', { applianceType, location, scheduledDateTime });
            return res.status(400).json({ success: false, message: 'Appliance type, all location details, and scheduled date/time are required for booking.' });
        }
        // Removed the separate latitude/longitude validation as they are now part of the location object.
        // It's assumed the frontend sends valid number types or empty strings for them.

        // Randomly assign an available technician
        const availableTechnicians = await User.find({ role: 'technician', kycStatus: 'approved', status: 'active' });
        const assignedTechnician = availableTechnicians.length > 0 ? availableTechnicians[Math.floor(Math.random() * availableTechnicians.length)] : null;

        const customer = await User.findById(userId);
        if (!customer) {
            console.warn('[BOOK SERVICE API] Logged-in user not found in database:', userId);
            return res.status(404).json({ success: false, message: 'Logged-in user not found in database.' });
        }

        const newJob = new Job({
            jobId: `J${Date.now().toString().slice(-6)}${Math.floor(Math.random() * 100).toString().padStart(2, '0')}`,
            userId: customer._id,
            customerName: customer.fullName,
            customerEmail: customer.email,
            customerPhoneNumber: customer.phoneNumber,
            applianceType,
            location, // Directly use the new structured location object from the request
            scheduledDateTime: new Date(scheduledDateTime),
            notes,
            status: 'Pending',
            assignedTechnicianId: assignedTechnician ? assignedTechnician._id : null,
            assignedTechnicianName: assignedTechnician ? assignedTechnician.fullName : 'Pending Assignment',
            // Removed the old jobLocation field, as 'location' now serves this purpose.
            isWarrantyClaim: isWarrantyClaim === 'true' || isWarrantyClaim === true,
            originalJobId: originalJobId || null,
        });

        console.log('[BOOK SERVICE API] Attempting to save new job to DB:', newJob.jobId, newJob.isWarrantyClaim ? '(Warranty Claim)' : '');
        await newJob.save();
        console.log('[BOOK SERVICE API] Job saved successfully:', newJob._id);

        res.status(201).json({ success: true, message: 'Service booked successfully! A technician will be assigned soon.', job: newJob });
    } catch (err) {
        console.error('[BOOK SERVICE API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during service booking.' });
    }
});


// Get user's jobs
app.get('/api/user/jobs', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[GET USER JOBS API] Request received for user ID:', req.user._id);
    try {
        const userJobs = await Job.find({ userId: req.user._id }).lean();
        console.log(`[GET USER JOBS API] Found ${userJobs.length} jobs for user.`);
        res.json({ success: true, jobs: userJobs });
    }
    catch (err) {
        console.error('[GET USER JOBS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching user jobs.' });
    }
});

// User cancels a job
app.post('/api/user/jobs/cancel', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[USER CANCEL JOB API] Request received for job ID:', req.body.jobId, 'by user:', req.user._id);
    try {
        const { jobId } = req.body;
        const job = await Job.findOneAndUpdate(
            { jobId: jobId, userId: req.user._id, status: { $in: ['Pending', 'Accepted'] } },
            { $set: { status: 'Cancelled' } },
            { new: true }
        ).lean();

        if (job) {
            console.log('[USER CANCEL JOB API] Job cancelled successfully:', job.jobId);
            res.json({ success: true, message: 'Job cancelled successfully!' });
        } else {
            console.warn('[USER CANCEL JOB API] Job not found, not associated with user, or cannot be cancelled:', jobId);
            res.status(404).json({ success: false, message: 'Job not found, not associated with your account, or cannot be cancelled at its current status.' });
        }
    }
    catch (err) {
        console.error('[USER CANCEL JOB API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job cancellation.' });
    }
});

// Process payment for a job (can be done by user, Superadmin, or Financeofficer)
app.post('/api/process-payment', authenticateToken, authorizeRoles(['user', 'Superadmin', 'Financeofficer']), async (req, res) => {
    console.log('[PROCESS PAYMENT API] Request received for job ID:', req.body.jobId, 'by user:', req.user._id);
    try {
        const { jobId, totalAmount, paymentMethod, paymentDetails } = req.body;

        const job = await Job.findOne({ jobId: jobId });

        if (!job) {
            console.warn(`[PROCESS PAYMENT API] Job ${jobId} not found for payment processing.`);
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const jobUserIdStr = job.userId ? job.userId.toString() : null;

        // Ensure current user has permission (job owner, superadmin, or finance officer)
        if (jobUserIdStr !== req.user._id.toString() && !['Superadmin', 'Financeofficer'].includes(req.user.role)) {
            console.warn(`[PROCESS PAYMENT API] Access denied for payment on job ${jobId}. User role: ${req.user.role}, Job owner: ${jobUserIdStr}`);
            return res.status(403).json({ success: false, message: 'Access denied to process payment for this job.' });
        }

        if (job.status !== 'Diagnosed' && job.status !== 'Completed') {
            console.warn(`[PROCESS PAYMENT API] Payment not allowed for job ${jobId}. Current status: ${job.status}.`);
            return res.status(400).json({ success: false, message: `Payment can only be processed for jobs that are 'Diagnosed' or 'Completed'. Current status: ${job.status}.` });
        }

        if (!totalAmount || isNaN(totalAmount) || totalAmount <= 0 || !paymentMethod) { 
            console.warn(`[PROCESS PAYMENT API] Missing/Invalid totalAmount or paymentMethod for job ${jobId}. Total: ${totalAmount}, Method: ${paymentMethod}`);
            return res.status(400).json({ success: false, message: 'Total amount (must be positive number) and payment method are required.' });
        }

        console.log(`[PROCESS PAYMENT API] Processing payment for Job ID: ${jobId}, Amount: ${totalAmount}, Method: ${paymentMethod}`);

        job.payment = {
            amount: parseFloat(totalAmount),
            method: paymentMethod,
            details: paymentDetails,
            status: 'Paid',
            paidAt: new Date()
        };
        job.status = 'Paid'; // Mark job as paid

        await job.save();

        // Create a PaymentIn transaction record
        await Transaction.create({
            transactionId: `TXN-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
            userId: job.userId,
            relatedUserId: job.assignedTechnicianId,
            jobId: job.jobId,
            type: 'PaymentIn',
            amount: job.payment.amount,
            status: 'Success',
            paymentMethod: job.payment.method,
            description: `Customer payment for Job ${job.jobId}`
        });

        // Calculate and update technician balance
        if (job.assignedTechnicianId && job.quotation && job.quotation.totalEstimate !== undefined) { 
            const grossAmount = job.quotation.totalEstimate;
            const appCommission = grossAmount * APP_COMMISSION_RATE;
            const amountBeforeTax = grossAmount - appCommission;
            const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
            const technicianNetEarning = amountBeforeTax - technicianTaxDeduction;

            console.log(`[PROCESS PAYMENT API - BALANCE UPDATE] Job ${job.jobId} paid. Calculated Net Earning for technician: ₹${technicianNetEarning.toFixed(2)}`);

            if (technicianNetEarning > 0) {
                try {
                    const updatedTechnician = await User.findByIdAndUpdate(
                        job.assignedTechnicianId,
                        { $inc: { balance: technicianNetEarning, jobsCompleted: 1 } }, // Increment jobsCompleted too
                        { new: true }
                    );
                    if (updatedTechnician) {
                        console.log(`[PROCESS PAYMENT API - BALANCE UPDATE] Technician ${updatedTechnician._id} balance updated to: ₹${updatedTechnician.balance.toFixed(2)}`);
                        // Create an Earning transaction record for the technician
                        await Transaction.create({
                            transactionId: `TXNE-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
                            userId: updatedTechnician._id,
                            relatedUserId: job.userId,
                            jobId: job.jobId,
                            type: 'Earning',
                            amount: technicianNetEarning,
                            status: 'Success',
                            description: `Technician earning for Job ${job.jobId}`
                        });
                        // Create a Commission transaction record for the platform
                         await Transaction.create({
                            transactionId: `TXNC-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
                            userId: job.assignedTechnicianId, // Associated with the technician's job
                            relatedUserId: req.user._id, // User who processed/triggered the payment (platform)
                            jobId: job.jobId,
                            type: 'Commission',
                            amount: appCommission,
                            status: 'Success',
                            description: `Platform commission from Job ${job.jobId}`
                        });

                    } else {
                        console.error(`[PROCESS PAYMENT API - BALANCE UPDATE ERROR] Technician ${job.assignedTechnicianId} not found when trying to update balance.`);
                    }
                } catch (updateError) {
                    console.error(`[PROCESS PAYMENT API - BALANCE UPDATE ERROR] Failed to update technician ${job.assignedTechnicianId} balance for job ${job.jobId}:`, updateError);
                }
            } else {
                console.log(`[PROCESS PAYMENT API - BALANCE UPDATE INFO] Net Earning for job ${job.jobId} is zero or negative. Technician balance not incremented.`);
            }
        } else {
            console.log(`[PROCESS PAYMENT API - BALANCE UPDATE INFO] Job ${job.jobId} has no assigned technician or quotation. Technician balance not incremented.`);
        }

        console.log(`[PROCESS PAYMENT API] Job ${jobId} successfully marked as Paid.`);

        res.json({ success: true, message: 'Payment processed successfully and job marked as Paid!', job: job.toJSON() });

    } catch (err) {
        console.error('[PROCESS PAYMENT API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during payment processing.' });
    }
});

// Fetch top 5 technicians by average rating
app.get('/api/top-technicians', async (req, res) => {
    console.log('[GET TOP TECHNICIANS API] Request received.');
    try {
        const topTechnicians = await User.find({ role: 'technician', kycStatus: 'approved', averageRating: { $gte: 0 } }) // Changed $gt:0 to $gte:0 to include 0 rated techs
            .sort({ averageRating: -1, ratingCount: -1 }) // Sort by rating (desc), then by review count (desc)
            .limit(5)
            .select('fullName skills averageRating ratingCount workingLocation') // Select relevant fields
            .lean();

        console.log(`[GET TOP TECHNICIANS API] Found ${topTechnicians.length} top technicians.`);
        res.json({ success: true, technicians: topTechnicians });
    } catch (error) {
        console.error('[GET TOP TECHNICIANS API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error while fetching top technicians.' });
    }
});

// AI Diagnosis Endpoint (Backend Integration with Gemini API)
app.post('/api/ai-diagnosis', async (req, res) => {
    console.log('[AI DIAGNOSIS API] Request received. Problem description length:', req.body.problemDescription ? req.body.problemDescription.length : 0);
    const { problemDescription } = req.body;

    if (!problemDescription) {
        return res.status(400).json({ success: false, message: 'Problem description is required for AI diagnosis.' });
    }

    try {
        // Construct chat history for the Gemini API call
        let chatHistory = [];
        chatHistory.push({ role: "user", parts: [{ text: `Provide a concise, preliminary diagnosis for an appliance problem. User input: "${problemDescription}". Suggest possible causes and basic troubleshooting steps. Keep it under 200 words.` }] });

        const payload = { contents: chatHistory };
        const apiKey = GEMINI_API_KEY; 

        if (!apiKey) {
            console.error('CRITICAL ERROR: Gemini API Key (API_KEY) not set in environment variables!');
            return res.status(500).json({ success: false, message: 'Server-side API key for AI diagnosis is missing. Please configure it.' });
        }

        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

        console.log('[AI DIAGNOSIS API] Sending request to Gemini API...');
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        console.log('Full Gemini API Response:', JSON.stringify(result, null, 2));

        // Extract the diagnosis text from the Gemini API response
        if (result.candidates && result.candidates.length > 0) {
            const firstCandidate = result.candidates[0];
            if (firstCandidate.content && firstCandidate.content.parts && firstCandidate.content.parts.length > 0) {
                const diagnosisText = firstCandidate.content.parts[0].text;
                console.log('[AI DIAGNOSIS API] Diagnosis received from Gemini.');
                res.json({ success: true, diagnosis: diagnosisText });
            } else {
                console.error('[AI DIAGNOSIS API] Gemini API Response Error: Candidate content or parts missing.', JSON.stringify(firstCandidate, null, 2));
                if (firstCandidate.safetyRatings && firstCandidate.safetyRatings.some(rating => rating.blocked)) {
                     res.status(400).json({ success: false, message: 'AI diagnosis blocked due to safety concerns with the input. Please rephrase.' });
                } else {
                    res.status(500).json({ success: false, message: 'Failed to get AI diagnosis from the model. Unexpected content structure within candidate.' });
                }
            }
        } else {
            console.error('[AI DIAGNOSIS API] Gemini API Response Error: No candidates found.', JSON.stringify(result, null, 2));
            if (result.promptFeedback && result.promptFeedback.safetyRatings && result.promptFeedback.safetyRatings.some(rating => rating.blocked)) {
                res.status(400).json({ success: false, message: 'AI diagnosis blocked due to safety concerns with the input. Please rephrase.' });
            } else {
                    res.status(500).json({ success: false, message: 'Failed to get AI diagnosis from the model. No candidates or unexpected top-level structure.' });
            }
        }
    } catch (error) {
        console.error('[AI DIAGNOSIS API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Server error during AI diagnosis.' });
    }
});

// API Route for Submitting User Review
app.post('/api/user/submit-review', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[SUBMIT REVIEW API] Request received for job ID:', req.body.jobId, 'by user:', req.user._id);
    try {
        const { jobId, rating, reviewText } = req.body;
        const userId = req.user._id;

        if (!jobId || rating === undefined || rating < 1 || rating > 5 || !reviewText) {
            console.warn('[SUBMIT REVIEW API] Validation failed: Missing or invalid fields.');
            return res.status(400).json({ success: false, message: 'Job ID, rating (1-5), and review text are required.' });
        }

        const job = await Job.findOne({ jobId: jobId, userId: userId });

        if (!job) {
            console.warn('[SUBMIT REVIEW API] Job not found or not associated with user:', jobId);
            return res.status(404).json({ success: false, message: 'Job not found or not associated with your account.' });
        }

        if (job.rating || job.reviewedAt) {
            console.warn('[SUBMIT REVIEW API] Job already reviewed:', jobId);
            return res.status(400).json({ success: false, message: 'This job has already been reviewed.' });
        }
        if (job.status !== 'Completed' && job.status !== 'Paid') {
            console.warn('[SUBMIT REVIEW API] Job not completed or paid, cannot review:', jobId, job.status);
            return res.status(400).json({ success: false, message: 'Only completed or paid jobs can be reviewed.' });
        }

        // Update the job with the review details
        job.rating = rating;
        job.reviewText = reviewText;
        job.reviewedAt = new Date(); 

        await job.save();
        console.log('[SUBMIT REVIEW API] Job updated with review:', job.jobId);

        // Update the technician's average rating
        const technician = await User.findById(job.assignedTechnicianId);
        if (technician) {
            const allTechnicianJobs = await Job.find({ assignedTechnicianId: technician._id, rating: { $exists: true, $ne: null } });
            let totalRating = 0;
            allTechnicianJobs.forEach(techJob => {
                totalRating += techJob.rating;
            });
            technician.averageRating = allTechnicianJobs.length > 0 ? totalRating / allTechnicianJobs.length : 0;
            technician.ratingCount = allTechnicianJobs.length; 
            await technician.save();
            console.log('[SUBMIT REVIEW API] Technician rating updated for:', technician.fullName);
        }

        res.json({ success: true, message: 'Review submitted successfully!' });

    } catch (err) {
        console.error('[SUBMIT REVIEW API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during review submission.' });
    }
});

// --- Support & Notifications API Endpoints ---

// API for authenticated users to fetch announcements
app.get('/api/user/announcements', authenticateToken, async (req, res) => {
    console.log('[GET USER ANNOUNCEMENTS API] Request received for user ID:', req.user._id, 'Role:', req.user.role);
    try {
        const userRole = req.user.role;
        const userCity = req.user.city; // Assuming user has a 'city' field

        // Build query to fetch announcements relevant to the user
        // Announcements targeted to 'All' or the user's specific role
        let queryConditions = [
            { targetAudience: 'All' },
            { targetAudience: userRole }
        ];

        // If the user is a Citymanager, also include announcements targeted to their assigned cities
        if (userRole === 'Citymanager' && req.user.assignedCities && req.user.assignedCities.length > 0) {
            queryConditions.push({ targetAudience: { $in: req.user.assignedCities } });
        }
        // If the user is a Serviceadmin, also include announcements targeted to their assigned skills
        if (userRole === 'Serviceadmin' && req.user.skills && req.user.skills.length > 0) {
            queryConditions.push({ targetAudience: { $in: req.user.skills } });
        }
        // If the user has a city, include announcements targeted to that city
        if (userCity) {
            queryConditions.push({ targetAudience: userCity });
        }

        const announcements = await Announcement.find({
            $or: queryConditions
        }).sort({ publishedOn: -1 }).lean(); // Sort by most recent

        console.log(`[GET USER ANNOUNCEMENTS API] Found ${announcements.length} announcements for user ${req.user._id}.`);
        res.json({ success: true, announcements: announcements });

    } catch (err) {
        console.error('[GET USER ANNOUNCEMENTS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching announcements.' });
    }
});

// API for authenticated users to create a new support ticket
app.post('/api/user/tickets/create', authenticateToken, async (req, res) => {
    console.log('[CREATE TICKET API] Request received from user:', req.user._id, 'Data:', req.body);
    try {
        const { subject, description, serviceType } = req.body; // serviceType is optional
        const raisedBy = req.user._id; // The ID of the logged-in user

        if (!subject || !description) {
            console.warn('[CREATE TICKET API] Missing required fields: subject or description.');
            return res.status(400).json({ success: false, message: 'Subject and description are required to create a ticket.' });
        }

        // Generate ticketId BEFORE creating the new Ticket instance
        const datePart = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const randomPart = crypto.randomBytes(2).toString('hex').toUpperCase();
        const newTicketId = `TST-${datePart}-${randomPart}`;

        const newTicket = new Ticket({
            ticketId: newTicketId, // Assign the generated ID
            raisedBy: raisedBy,
            subject: subject,
            description: description,
            serviceType: serviceType || 'General', // Default to 'General' if not provided
            status: 'Open', // New tickets are always 'Open'
            priority: 'Medium' // Default priority
        });

        await newTicket.save();
        console.log('[CREATE TICKET API] New ticket created successfully:', newTicket.ticketId);

        res.status(201).json({ success: true, message: 'Your support ticket has been submitted successfully! We will get back to you soon.', ticket: newTicket });

    } catch (err) {
        console.error('[CREATE TICKET API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during ticket submission.' });
    }
});


// --- Technician Specific API Endpoints ---

// Get technician's jobs
app.get('/api/technician/jobs', isAuthenticated, isTechnician, async (req, res) => {
    console.log('[GET TECHNICIAN JOBS API] Request received for technician ID:', req.session.user.id);
    try {
        const technicianObjectId = new mongoose.Types.ObjectId(req.session.user.id);

        const technicianJobs = await Job.find({ assignedTechnicianId: technicianObjectId })
            .populate('userId', 'fullName email phoneNumber')
            .lean();
        console.log(`[GET TECHNICIAN JOBS API] Found ${technicianJobs.length} jobs for technician.`);
        res.json({ success: true, jobs: technicianJobs });
    } catch (err) {
        console.error('[GET TECHNICIAN JOBS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching technician jobs.' });
    }
});

// Technician accepts a job
app.post('/api/technician/jobs/accept', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[TECHNICIAN ACCEPT JOB API] Request received for job ID:', req.body.jobId, 'by technician:', req.user._id);
    try {
        const { jobId } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.user._id);
        const technicianName = req.user.fullName;

        const job = await Job.findOneAndUpdate(
            {
                jobId: jobId,
                status: 'Pending',
                $or: [
                    { assignedTechnicianId: null }, // Job not assigned yet
                    { assignedTechnicianId: technicianObjectId } // Job already assigned to THIS technician (e.g. from admin)
                ]
            },
            { $set: { assignedTechnicianId: technicianObjectId, assignedTechnicianName: technicianName, status: 'Accepted' } },
            { new: true }
        ).lean();

        if (job) {
            console.log('[TECHNICIAN ACCEPT JOB API] Job accepted successfully:', job.jobId);
            res.json({ success: true, message: 'Job accepted successfully!', job: job });
        } else {
            console.warn('[TECHNICIAN ACCEPT JOB API] Job not found, not in pending status, or already assigned:', jobId);
            res.status(404).json({ success: false, message: 'Job not found, not in pending status, or already assigned.' });
        }
    } catch (err) {
        console.error('[TECHNICIAN ACCEPT JOB API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job acceptance.' });
    }
});

// Technician starts a job
app.post('/api/technician/jobs/start', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[TECHNICIAN START JOB API] Request received for job ID:', req.body.jobId, 'by technician:', req.user._id);
    try {
        const { jobId } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.user._id);

        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianObjectId, status: 'Accepted' },
            { $set: { status: 'In Progress' } },
            { new: true }
        ).lean();

        if (job) {
            console.log('[TECHNICIAN START JOB API] Job status updated to In Progress:', job.jobId);
            res.json({ success: true, message: 'Job status updated to In Progress!', job: job });
        } else {
            console.warn('[TECHNICIAN START JOB API] Job not found, not assigned to technician, or not in Accepted status:', jobId);
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in Accepted status.' });
        }
    } catch (err) {
        console.error('[TECHNICIAN START JOB API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job start.' });
    }
});

// Technician completes a job (with proof images)
app.post('/api/technician/jobs/complete', authenticateToken, authorizeRoles(['technician']), upload.array('proofImages'), async (req, res) => {
    console.log('[TECHNICIAN COMPLETE JOB API] Request received for job ID:', req.body.jobId, 'by technician:', req.user._id);
    try {
        const { jobId } = req.body;
        const technicianId = req.user._id; 
        
        // Convert uploaded files (if any) to Base64 strings
        const proofImages = req.files ? req.files.map(file => `data:${file.mimetype};base64,${file.buffer.toString('base64')}`) : [];
        console.log(`[TECHNICIAN COMPLETE JOB API] Received ${proofImages.length} proof images.`);

        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianId, status: { $in: ['In Progress', 'Diagnosed'] } },
            {
                $set: {
                    status: 'Completed',
                    completedAt: new Date(),
                    proofImages: proofImages // Save Base64 strings
                }
            },
            { new: true }
        );

        if (job) {
            console.log('[TECHNICIAN COMPLETE JOB API] Job marked as Completed and proof images saved:', job.jobId);
            res.json({ success: true, message: 'Job marked as Completed and proof images saved!', job: job.toJSON() });
        } else {
            console.warn('[TECHNICIAN COMPLETE JOB API] Job not found, not assigned to technician, or not in correct status for completion:', jobId);
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or not in correct status for completion.' });
        }
    } catch (err) {
        console.error('[TECHNICIAN COMPLETE JOB API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job completion.' });
    }
});
app.post('/api/technician/jobs/reject', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[TECHNICIAN REJECT JOB API] Request received for job ID:', req.body.jobId, 'by technician:', req.user._id);
    try {
        const { jobId } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.user._id);

        // Find the job and update its status to 'Cancelled'
        const job = await Job.findOneAndUpdate(
            { 
                jobId: jobId, 
                assignedTechnicianId: technicianObjectId, 
                status: 'Pending' 
            },
            { $set: { status: 'Cancelled' } },
            { new: true }
        ).lean();

        if (job) {
            console.log('[TECHNICIAN REJECT JOB API] Job rejected successfully:', job.jobId);
            res.json({ success: true, message: 'Job rejected successfully!' });
        } else {
            console.warn('[TECHNICIAN REJECT JOB API] Job not found, not assigned to technician, or not in Pending status:', jobId);
            res.status(404).json({ success: false, message: 'Job not found, not assigned to you, or cannot be rejected at this time.' });
        }
    } catch (err) {
        console.error('[TECHNICIAN REJECT JOB API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during job rejection.' });
    }
});
// NEW: Endpoint to process COD Payment
app.post('/api/process-cod-payment', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[PROCESS COD PAYMENT API] Request received for job ID:', req.body.jobId);
    try {
        const { jobId, amount } = req.body;
        const job = await Job.findOne({ jobId });
        if (!job) {
             return res.status(404).json({ success: false, message: 'Job not found.' });
        }
        
        const paymentDetails = {
            status: 'success',
            method: 'COD',
            transactionId: `COD-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`
        };

        const result = await processAndSavePayment({
            jobId,
            totalAmount: amount,
            paymentMethod: 'COD',
            paymentDetails
        });

        if (result.success) {
            res.json({ success: true, message: result.message, paymentId: paymentDetails.transactionId });
        } else {
            res.status(500).json({ success: false, message: result.message });
        }
    } catch (error) {
        console.error('Error in /api/process-cod-payment:', error);
        res.status(500).json({ success: false, message: 'Internal server error during COD payment processing.' });
    }
});
// NEW: Dummy Razorpay endpoint for development
app.post('/api/create-razorpay-order', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[DUMMY RAZORPAY] Dummy order creation endpoint hit. Not processing real payment.');
    res.json({
        success: true,
        key: 'dummy-key',
        order: {
            id: `order_dummy_${Date.now()}`,
            amount: req.body.amount,
            currency: 'INR'
        }
    });
});
// NEW: Dummy Razorpay verification endpoint for development
app.post('/api/verify-razorpay-payment', authenticateToken, authorizeRoles(['user']), async (req, res) => {
    console.log('[DUMMY RAZORPAY] Dummy payment verification endpoint hit. Not processing real payment.');
    
    const { jobId, amount } = req.body;
    
    const paymentDetails = {
        status: 'success',
        method: 'Razorpay (Dummy)',
        transactionId: `rzp_dummy_${Date.now()}`
    };

    const result = await processAndSavePayment({
        jobId,
        totalAmount: amount,
        paymentMethod: 'Razorpay',
        paymentDetails
    });

    if (result.success) {
        res.json({ success: true, message: result.message, paymentId: paymentDetails.transactionId });
    } else {
        res.status(500).json({ success: false, message: result.message });
    }
});
// Technician submits diagnosis and quotation
app.post('/api/technician/diagnosis', authenticateToken, authorizeRoles(['technician']), upload.array('appliancePhotos'), async (req, res) => {
    console.log('[TECHNICIAN DIAGNOSIS API] Request received for job ID:', req.body.jobId, 'by technician:', req.user._id);
    try {
        const { jobId, faultyParts, technicianRemarks, partCost, laborCost, travelCharges, totalEstimate } = req.body;
        const technicianObjectId = new mongoose.Types.ObjectId(req.user._id);

        // Convert uploaded files to Base64 strings for storage (if any)
        const proofImages = req.files ? req.files.map(file => `data:${file.mimetype};base64,${file.buffer.toString('base64')}`) : [];
        console.log(`[TECHNICIAN DIAGNOSIS API] Received ${proofImages.length} appliance photos.`);

        let parsedFaultyParts = [];
        if (faultyParts) {
            if (typeof faultyParts === 'string') {
                try {
                    parsedFaultyParts = JSON.parse(faultyParts);
                } catch (e) {
                    parsedFaultyParts = faultyParts.split(',').map(part => part.trim()).filter(part => part.length > 0);
                    console.warn(`[TECHNICIAN DIAGNOSIS API] faultyParts was not valid JSON. Parsed as comma-separated string: "${faultyParts}" ->`, parsedFaultyParts);
                }
            } else if (Array.isArray(faultyParts)) {
                parsedFaultyParts = faultyParts;
            } else {
                console.warn(`[TECHNICIAN DIAGNOSIS API] Unexpected type for faultyParts: ${typeof faultyParts}. Setting to empty array.`);
            }
        }

        const job = await Job.findOneAndUpdate(
            { jobId: jobId, assignedTechnicianId: technicianObjectId, status: { $in: ['In Progress', 'Accepted'] } },
            {
                $set: {
                    faultyParts: parsedFaultyParts, // Use the corrected faultyParts
                    technicianRemarks,
                    quotation: {
                        partCost: parseFloat(partCost),
                        laborCost: parseFloat(laborCost),
                        travelCharges: parseFloat(travelCharges),
                        totalEstimate: parseFloat(totalEstimate),
                        createdAt: new Date()
                    },
                    status: 'Diagnosed',
                    proofImages: proofImages // Store images here too if desired for diagnosis
                }
            },
            { new: true }
        ).lean();

        if (job) {
            console.log('[TECHNICIAN DIAGNOSIS API] Diagnosis & Quotation saved successfully for job:', job.jobId);
            res.json({ success: true, message: 'Diagnosis & Quotation saved successfully.', job });
        } else {
            console.warn('[TECHNICIAN DIAGNOSIS API] Job not found, not assigned to technician, or not in correct status for diagnosis:', jobId);
            res.status(404).json({ success: false, message: 'Job not found or not assigned to you.' });
        }
    } catch (err) {
        console.error('[TECHNICIAN DIAGNOSIS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error during diagnosis submission.' });
    }
});

// API for updating technician's availability settings
app.post('/api/technician/update-availability', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[UPDATE AVAILABILITY API] Request received for technician:', req.user._id, 'Data:', req.body);
    try {
        const userId = req.user._id;
        const { availableDays, startTime, endTime, emergencyCalls } = req.body;

        const technician = await User.findById(userId);
        if (!technician) {
            console.warn('[UPDATE AVAILABILITY API] Technician not found:', userId);
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        technician.availability = {
            availableDays: availableDays || [],
            startTime: startTime || '09:00',
            endTime: endTime || '18:00',
            emergencyCalls: emergencyCalls !== undefined ? emergencyCalls : false
        };
        await technician.save();
        console.log('[UPDATE AVAILABILITY API] Availability updated successfully for technician:', userId);
        res.json({ success: true, message: 'Availability updated successfully!' });

    } catch (error) {
        console.error('[UPDATE AVAILABILITY API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating availability.' });
    }
});

// API for updating technician's working location and service radius
app.post('/api/technician/update-location', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[UPDATE LOCATION API] Request received for technician:', req.user._id, 'Data:', req.body);
    try {
        const userId = req.user._id;
        const { workingLocation } = req.body; 

        const technician = await User.findById(userId);
        if (!technician) {
            console.warn('[UPDATE LOCATION API] Technician not found:', userId);
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        // NEW: Directly use the new structured workingLocation object
        technician.workingLocation = {
            pincode: workingLocation.pincode || '',
            city: workingLocation.city || '',
            state: workingLocation.state || '',
            street: workingLocation.street || '',
            houseBuilding: workingLocation.houseBuilding || '',
            radiusKm: workingLocation.radiusKm || 10, // Ensure a default value
            latitude: workingLocation.latitude ? parseFloat(workingLocation.latitude) : null,
            longitude: workingLocation.longitude ? parseFloat(workingLocation.longitude) : null
        };
        
        await technician.save();
        console.log('[UPDATE LOCATION API] Location settings updated successfully for technician:', userId);
        res.json({ success: true, message: 'Location settings updated successfully!' });

    } catch (error) {
        console.error('[UPDATE LOCATION API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating location settings.' });
    }
});

// API for updating technician's bank/UPI payment details
app.post('/api/technician/update-payment-details', authenticateToken, authorizeRoles(['technician']), async (req, res) => {
    console.log('[UPDATE PAYMENT DETAILS API] Request received for technician:', req.user._id, 'Data:', req.body);
    try {
        const userId = req.user._id;
        const { bankName, accountNumber, ifscCode, upiId } = req.body;

        const technician = await User.findById(userId);
        if (!technician) {
            console.warn('[UPDATE PAYMENT DETAILS API] Technician not found:', userId);
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        technician.bankDetails = {
            bankName: bankName || '',
            accountNumber: accountNumber || '',
            ifscCode: ifscCode || '',
            upiId: upiId || ''
        };

        await technician.save();
        console.log('[UPDATE PAYMENT DETAILS API] Payment details updated successfully for technician:', userId);
        res.json({ success: true, message: 'Payment details updated successfully!' });

    } catch (error) {
        console.error('[UPDATE PAYMENT DETAILS API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error updating payment details.' });
    }
});

// API for technician withdrawal (deducts from balance) - accessible by technician and financeofficer
app.post('/api/technician/withdraw', authenticateToken, authorizeRoles(['technician', 'Financeofficer']), async (req, res) => {
    console.log('[TECHNICIAN WITHDRAWAL API] Request received for technician:', req.user._id, 'Amount:', req.body.amount, 'By Role:', req.user.role);
    try {
        const userId = req.user._id; // User initiating the request
        const { amount, technicianId: targetTechnicianId } = req.body; // targetTechnicianId is optional, used by finance officer

        // Determine the actual technician whose balance is being affected
        const actualTechnicianId = req.user.role === 'technician' ? userId : targetTechnicianId;

        if (!actualTechnicianId) {
            return res.status(400).json({ success: false, message: 'Technician ID is required for withdrawal.' });
        }
        
        if (amount <= 0) {
            console.warn('[TECHNICIAN WITHDRAWAL API] Invalid withdrawal amount:', amount);
            return res.status(400).json({ success: false, message: 'Withdrawal amount must be positive.' });
        }

        const technician = await User.findById(actualTechnicianId);
        if (!technician) {
            console.warn('[TECHNICIAN WITHDRAWAL API] Technician not found:', actualTechnicianId);
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        if (technician.balance < amount) {
            console.warn('[TECHNICIAN WITHDRAWAL API] Insufficient balance for withdrawal for technician:', actualTechnicianId, 'Balance:', technician.balance, 'Requested:', amount);
            return res.status(400).json({ success: false, message: 'Insufficient balance for withdrawal.' });
        }

        const hasBankDetails = technician.bankDetails && technician.bankDetails.accountNumber && technician.bankDetails.bankName && technician.bankDetails.ifscCode;
        const hasUpiId = technician.bankDetails && technician.bankDetails.upiId;

        if (!hasBankDetails && !hasUpiId) {
            console.warn('[TECHNICIAN WITHDRAWAL API] No payment details found for technician:', actualTechnicianId);
            return res.status(400).json({ success: false, message: 'Please provide either complete bank account details or a UPI ID before withdrawing.' });
        }
        
        technician.balance -= amount;
        await technician.save();
        
        // Record the payout transaction as pending or success (depending on whether it's truly automated or needs manual approval)
        await Transaction.create({
            transactionId: `TXNP-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
            userId: actualTechnicianId, // The technician receiving payout
            relatedUserId: req.user._id, // The admin/technician who initiated/approved it
            type: 'Payout',
            amount: amount,
            status: 'Pending', // Mark as pending, finance officer will change to Success upon actual transfer
            description: `Payout request for technician ${technician.fullName}`
        });

        console.log(`[TECHNICIAN WITHDRAWAL API] Withdrawal of ₹${amount.toFixed(2)} initiated successfully for technician ${actualTechnicianId}. New balance: ₹${technician.balance.toFixed(2)}`);
        res.json({ success: true, message: `Withdrawal of ₹${amount.toFixed(2)} initiated successfully. Your new balance is ₹${technician.balance.toFixed(2)}. Processing may take 1-2 business days.` });

    } catch (error) {
        console.error('[TECHNICIAN WITHDRAWAL API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error during withdrawal.' });
    }
});

// --- General API Endpoints (Shared/Utility) ---

// Get single job details (accessible by job owner, assigned technician, or any admin role)
app.get('/api/jobs/:jobId', authenticateToken, authorizeRoles(['user', 'technician', 'Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
    console.log('[GET JOB DETAILS API] Request received for job ID:', req.params.jobId, 'by user:', req.user._id);
    try {
        const jobId = req.params.jobId;
        const job = await Job.findOne({ jobId: jobId }).lean();

        if (!job) {
            console.warn('[GET JOB DETAILS API] Job not found:', jobId);
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const jobUserIdStr = job.userId ? job.userId.toString() : null;
        const jobAssignedTechIdStr = job.assignedTechnicianId ? job.assignedTechnicianId.toString() : null;

        // Check if the current user has permission to view this job
        // If user is Superadmin, or if user is job owner, or if user is assigned technician, allow.
        // The authorizeRoles middleware handles other admin roles access.
        if (req.user.role === 'Superadmin' || jobUserIdStr === req.user._id.toString() || jobAssignedTechIdStr === req.user._id.toString()) {
            const customer = await User.findById(job.userId).lean();
            const technician = job.assignedTechnicianId ? await User.findById(job.assignedTechnicianId).lean() : null;

            const jobDetails = {
                ...job,
                customerName: customer ? customer.fullName : 'N/A',
                customerEmail: customer ? customer.email : 'N/A',
                customerPhoneNumber: customer ? customer.phoneNumber : 'N/A',
                technicianName: technician ? technician.fullName : 'N/A',
                technicianEmail: technician ? technician.email : 'N/A',
                technicianPhoneNumber: technician ? technician.phoneNumber : 'N/A'
            };
            console.log('[GET JOB DETAILS API] Successfully fetched job details for:', jobId);
            res.json({ success: true, job: jobDetails });
        } else {
            console.warn('[GET JOB DETAILS API] Access denied to job:', jobId, 'for user:', req.user._id, 'Role:', req.user.role);
            res.status(403).json({ success: false, message: 'Access denied to this job.' });
        }
    }
    catch (err) {
        console.error('[GET JOB DETAILS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching job details.' });
    }
});


// Backend endpoint to perform reverse geocoding
app.post('/api/reverse-geocode', async (req, res) => {
    console.log('[REVERSE GEOCODE API] Request received for lat/lon:', req.body.latitude, req.body.longitude);
    const { latitude, longitude } = req.body;

    if (!latitude || !longitude) {
        return res.status(400).json({ success: false, message: 'Latitude and Longitude are required.' });
    }

    if (!GOOGLE_MAPS_API_KEY) {
        console.error('CRITICAL ERROR: VITE_GOOGLE_MAPS_API_KEY is not set in environment variables!');
        return res.status(500).json({ success: false, message: 'Server-side Google Maps API key is missing.' });
    }

    try {
        const geocodingUrl = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${latitude},${longitude}&key=${GOOGLE_MAPS_API_KEY}`;
        const response = await fetch(geocodingUrl);
        const data = await response.json();

        if (data.status === 'OK' && data.results && data.results.length > 0) {
            const result = data.results[0];
            const formattedAddress = result.formatted_address;
            
            // START: NEW LOGIC to extract components for structured address
            let structuredAddress = {
                pincode: '',
                state: '',
                city: '',
                houseBuilding: '',
                street: '',
                latitude: latitude,
                longitude: longitude
            };

            const street_number = result.address_components.find(c => c.types.includes('street_number'))?.long_name || '';
            const route = result.address_components.find(c => c.types.includes('route'))?.long_name || '';
            const sublocality = result.address_components.find(c => c.types.includes('sublocality'))?.long_name || '';
            const locality = result.address_components.find(c => c.types.includes('locality'))?.long_name || '';
            
            structuredAddress.pincode = result.address_components.find(c => c.types.includes('postal_code'))?.long_name || '';
            structuredAddress.state = result.address_components.find(c => c.types.includes('administrative_area_level_1'))?.long_name || '';
            structuredAddress.city = locality || '';
            structuredAddress.houseBuilding = street_number || '';
            structuredAddress.street = route || sublocality || '';
            // END: NEW LOGIC

            console.log('[REVERSE GEOCODE API] Successfully resolved address:', formattedAddress);
            // UPDATED: Now returning both the full address string and the new structuredAddress object
            res.json({ success: true, address: formattedAddress, structuredAddress: structuredAddress });
        } else {
            console.error('[REVERSE GEOCODE API] Google Geocoding API Error:', data.status, data.error_message || 'No results found');
            res.status(400).json({ success: false, message: data.error_message || 'Could not resolve address for given coordinates.' });
        }
    } catch (error) {
        console.error('[REVERSE GEOCODE API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error during reverse geocoding.' });
    }
});

// Backend endpoint for Google Places Autocomplete (securely uses API key)
app.post('/api/places-autocomplete', async (req, res) => {
    console.log('[PLACES AUTOCOMPLETE API] Request received for query:', req.body.query);
    const { query } = req.body;

    if (!query) {
        return res.status(400).json({ success: false, message: 'Query parameter is required for place autocomplete.' });
    }

    if (!GOOGLE_MAPS_API_KEY) {
        console.error('CRITICAL ERROR: VITE_GOOGLE_MAPS_API_KEY is not set in environment variables!');
        return res.status(500).json({ success: false, message: 'Server-side Google Maps API key is missing for Places Autocomplete.' });
    }

    try {
        const autocompleteUrl = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(query)}&key=${GOOGLE_MAPS_API_KEY}&components=country:in`;
        
        const response = await fetch(autocompleteUrl);
        const data = await response.json();

        if (data.status === 'OK' && data.predictions) {
            console.log(`[PLACES AUTOCOMPLETE API] Found ${data.predictions.length} predictions.`);
            res.json({ success: true, predictions: data.predictions });
        } else {
            console.error('[PLACES AUTOCOMPLETE API] Google Places Autocomplete API Error:', data.status, data.error_message || 'No predictions found');
            res.status(400).json({ success: false, message: data.error_message || 'Could not fetch location suggestions.' });
        }
    } catch (error) {
        console.error('[PLACES AUTOCOMPLETE API ERROR]:', error);
        res.status(500).json({ success: false, message: 'Internal server error during places autocomplete.' });
    }
});


// Contact Form Submission Endpoint
app.post('/api/contact', async (req, res) => {
    console.log('[CONTACT FORM] Received data for new message from:', req.body.email);
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
        console.warn('[CONTACT FORM] Validation Failed: Missing fields.');
        return res.status(400).json({ success: false, message: 'All fields (name, email, subject, message) are required.' });
    }

    try {
        const newContactMessage = new ContactMessage({
            name,
            email,
            subject,
            message
        });
        console.log('[CONTACT FORM] Attempting to save new message to MongoDB.');
        await newContactMessage.save(); 
        console.log('[CONTACT FORM] New Contact Message saved to MongoDB SUCCESSFULLY:', newContactMessage._id);
        res.status(201).json({ success: true, message: 'Your message has been sent successfully! We will get back to you soon.' });
    } catch (error) {
        console.error('[CONTACT FORM SUBMISSION ERROR]: Failed to save message to MongoDB.', error); 
        res.status(500).json({ success: false, message: 'Failed to send message. Please try again.' });
    }
});

// --- Admin API Endpoints (Superadmin, Citymanager, Serviceadmin, Financeofficer, Supportagent) ---

// Superadmin Dashboard Overview
app.get('/api/admin/dashboard-overview', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    console.log('[ADMIN DASHBOARD OVERVIEW API] Request received by Superadmin:', req.user._id);
    try {
        const totalJobs = await Job.countDocuments();
        const activeTechnicians = await User.countDocuments({ role: 'technician', kycStatus: 'approved', status: 'active' });
        const totalCustomers = await User.countDocuments({ role: 'user' });
        const pendingApprovals = await User.countDocuments({ role: 'technician', kycStatus: 'pending' });
        const openTickets = await Ticket.countDocuments({ status: { $in: ['Open', 'In Progress', 'Escalated'] } });
        const activeLocations = await Location.countDocuments({ status: 'active' });
        const activeCoupons = await Promotion.countDocuments({ status: 'Active', expiryDate: { $gt: Date.now() } });

        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0); // Last day of current month

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
                    _id: null,
                    totalRevenue: { $sum: '$payment.amount' }
                }
            }
        ]);
        const revenueThisMonth = revenueThisMonthResult.length > 0 ? revenueThisMonthResult[0].totalRevenue : 0;
        
        // Total transactions last 30 days
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const totalTransactionsLast30Days = await Transaction.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });

        console.log('[ADMIN DASHBOARD OVERVIEW API] Overview data fetched successfully.');
        res.json({
            success: true,
            data: {
                totalJobs,
                activeTechnicians,
                totalCustomers,
                revenueThisMonth: parseFloat(revenueThisMonth.toFixed(2)),
                pendingApprovals,
                openTickets,
                totalTransactionsLast30Days,
                activeLocations,
                activeCoupons
            }
        });

    } catch (err) {
        console.error('[ADMIN DASHBOARD OVERVIEW API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching dashboard overview.' });
    }
});

// Admin gets all users (accessible by Superadmin, Citymanager, Serviceadmin, Financeofficer, Supportagent)
app.get('/api/admin/users', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
    console.log('[ADMIN GET USERS API] Request received by user:', req.user._id, 'Role:', req.user.role);
    try {
        let query = {};
        // Citymanager can only view users/technicians in their assigned cities
        if (req.user.role === 'Citymanager' && req.user.assignedCities && req.user.assignedCities.length > 0) {
            query.$or = [
                { role: 'user', city: { $in: req.user.assignedCities } },
                { role: 'technician', 'workingLocation.city': { $in: req.user.assignedCities } }
            ];
        } 
        // Service Admin can only view technicians under their assigned services/skills
        else if (req.user.role === 'Serviceadmin' && req.user.skills && req.user.skills.length > 0) {
            query.role = 'technician';
            query.skills = { $in: req.user.skills };
        }
        
        const users = await User.find(query).select('-password').lean(); // Exclude passwords
        console.log(`[ADMIN GET USERS API] Found ${users.length} users.`);
        res.json({ success: true, users: users });
    }
    catch (err) {
        console.error('[ADMIN GET USERS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching users.' });
    }
});

// Admin assigns technician to a job (accessible by Superadmin and Serviceadmin)
app.post('/api/admin/jobs/assign-technician', authenticateToken, authorizeRoles(['Superadmin', 'Serviceadmin']), async (req, res) => {
    console.log('[ADMIN ASSIGN TECHNICIAN API] Request received to assign technician to job:', req.body.jobId, 'technician:', req.body.technicianId);
    try {
        const { jobId, technicianId } = req.body;

        const job = await Job.findOne({ jobId: jobId });
        if (!job) {
            console.warn('[ADMIN ASSIGN TECHNICIAN API] Job not found:', jobId);
            return res.status(404).json({ success: false, message: 'Job not found.' });
        }

        const technician = await User.findById(technicianId);
        if (!technician || technician.role !== 'technician' || technician.kycStatus !== 'approved') {
            console.warn('[ADMIN ASSIGN TECHNICIAN API] Technician not found or not approved:', technicianId);
            return res.status(404).json({ success: false, message: 'Technician not found or not an approved technician.' });
        }

        // Service Admin specific check
        if (req.user.role === 'Serviceadmin' && !technician.skills.some(skill => req.user.skills.includes(skill))) {
            return res.status(403).json({ success: false, message: 'Service Admin can only assign technicians under their assigned services.' });
        }

        job.assignedTechnicianId = technician._id;
        job.assignedTechnicianName = technician.fullName;
        if (job.status === 'Pending') { // Only change status if it's still pending
            job.status = 'Accepted';
        }

        await job.save();
        console.log(`[ADMIN ASSIGN TECHNICIAN API] Technician ${technician.fullName} assigned to job ${jobId}.`);
        res.json({ success: true, message: `Technician ${technician.fullName} assigned to job ${jobId}.`, job: job.toJSON() });

    } catch (err) {
        console.error('[ADMIN ASSIGN TECHNICIAN API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while assigning technician.' });
    }
});

// Admin grants technician KYC approval (only for Superadmin and Serviceadmin)
app.post('/api/admin/users/:userId/grant-technician', authenticateToken, authorizeRoles(['Superadmin', 'Serviceadmin']), async (req, res) => {
    console.log('[ADMIN GRANT TECHNICIAN KYC] Request received for user:', req.params.userId);
    try {
        const userId = req.params.userId;
        const user = await User.findById(userId);

        if (!user || user.role !== 'technician') {
            console.warn('[ADMIN GRANT TECHNICIAN KYC] User not found or not a technician:', userId);
            return res.status(404).json({ success: false, message: 'User not found or not a technician role.' });
        }

        if (user.kycStatus === 'approved') {
            console.warn('[ADMIN GRANT TECHNICIAN KYC] Technician already approved:', userId);
            return res.status(400).json({ success: false, message: 'Technician is already approved.' });
        }

        // --- REMOVED: Service Admin specific check for skills ---
        // if (req.user.role === 'Serviceadmin' && !user.skills.some(skill => req.user.skills.includes(skill))) {
        //     return res.status(403).json({ success: false, message: 'You can only approve KYC for technicians under your assigned services.' });
        // }

        user.kycStatus = 'approved';
        await user.save();
        console.log('[ADMIN GRANT TECHNICIAN KYC] Technician KYC approved successfully for:', userId);
        res.json({ success: true, message: 'Technician KYC approved successfully.', user: user.toJSON() });
    }
    catch (err) {
        console.error('[ADMIN GRANT TECHNICIAN KYC ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while granting technician KYC approval.' });
    }
});
app.get('/api/serviceadmin/all-pending-kyc-technicians', authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const pendingTechnicians = await User.find({
            role: 'technician',
            kycStatus: 'pending'
        })
        .select('fullName email phoneNumber pan aadhaar skills status kycStatus averageRating ratingCount') // आवश्यक फ़ील्ड चुनें
        .lean(); // तेज़ क्वेरी निष्पादन के लिए .lean() का उपयोग करें

        res.json({
            success: true,
            technicians: pendingTechnicians,
            message: "Serviceadmin समीक्षा के लिए सभी लंबित KYC तकनीशियनों को सफलतापूर्वक प्राप्त किया गया।"
        });
    } catch (error) {
        console.error('Serviceadmin के लिए सभी लंबित KYC तकनीशियनों को प्राप्त करने में त्रुटि:', error);
        res.status(500).json({ success: false, message: 'लंबित KYC तकनीशियनों को प्राप्त करने में विफल।' });
    }
});

// Admin rejects technician KYC approval (only for Superadmin and Serviceadmin)
app.post('/api/admin/users/:userId/reject-technician', authenticateToken, authorizeRoles(['Superadmin', 'Serviceadmin']), async (req, res) => {
    console.log('[ADMIN REJECT TECHNICIAN KYC] Request received for user:', req.params.userId);
    try {
        const userId = req.params.userId;
        const user = await User.findById(userId);

        if (!user || user.role !== 'technician') {
            console.warn('[ADMIN REJECT TECHNICIAN KYC] User not found or not a technician:', userId);
            return res.status(404).json({ success: false, message: 'User not found or not a technician role.' });
        }

        if (user.kycStatus === 'rejected') {
            console.warn('[ADMIN REJECT TECHNICIAN KYC] Technician already rejected:', userId);
            return res.status(400).json({ success: false, message: 'Technician KYC is already rejected.' });
        }

        // --- REMOVED: Service Admin specific check for skills ---
        // if (req.user.role === 'Serviceadmin' && !user.skills.some(skill => req.user.skills.includes(skill))) {
        //     return res.status(403).json({ success: false, message: 'You can only reject KYC for technicians under your assigned services.' });
        // }

        user.kycStatus = 'rejected';
        await user.save();
        console.log('[ADMIN REJECT TECHNICIAN KYC] Technician KYC rejected successfully for:', userId);
        res.json({ success: true, message: 'Technician KYC rejected successfully.', user: user.toJSON() });
    } catch (err) {
        console.error('[ADMIN REJECT TECHNICIAN KYC ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while rejecting technician KYC.' });
    }
});

// Admin gets all jobs (accessible by Superadmin and Serviceadmin, Citymanager)
app.get('/api/admin/jobs', authenticateToken, authorizeRoles(['Superadmin', 'Serviceadmin', 'Citymanager']), async (req, res) => {
    console.log('[ADMIN GET ALL JOBS API] Request received by user:', req.user._id, 'Role:', req.user.role);
    try {
        let query = {};
        // Filter jobs based on admin role
        if (req.user.role === 'Citymanager' && req.user.assignedCities && req.user.assignedCities.length > 0) {
            query['location.city'] = { $in: req.user.assignedCities };
        } else if (req.user.role === 'Serviceadmin' && req.user.skills && req.user.skills.length > 0) {
            query.applianceType = { $in: req.user.skills };
        }

        const jobs = await Job.find(query)
            .populate('userId', 'fullName email phoneNumber')
            .populate('assignedTechnicianId', 'fullName email phoneNumber')
            .lean();

        const enhancedJobs = jobs.map(job => ({
            ...job,
            customerName: job.userId ? job.userId.fullName : 'N/A',
            customerEmail: job.userId ? job.userId.email : 'N/A',
            customerPhoneNumber: job.userId ? job.userId.phoneNumber : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Pending Assignment',
            technicianEmail: job.assignedTechnicianId ? job.assignedTechnicianId.email : 'N/A',
            technicianPhoneNumber: job.assignedTechnicianId ? job.assignedTechnicianId.phoneNumber : 'N/A',
            userId: job.userId ? job.userId._id.toString() : null,
            assignedTechnicianId: job.assignedTechnicianId ? job.assignedTechnicianId._id.toString() : null
        }));

        console.log(`[ADMIN GET ALL JOBS API] Found ${enhancedJobs.length} jobs.`);
        res.json({ success: true, jobs: enhancedJobs });
    } catch (err) {
        console.error('[ADMIN GET ALL JOBS API ERROR]:', err);
        res.status(500).json({ success: false, message: 'Internal server error while fetching all jobs.' });
    }
});
app.get('/api/serviceadmin/all-pending-kyc-technicians', authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const pendingTechnicians = await User.find({
            role: 'technician',
            kycStatus: 'pending'
        })
        .select('fullName email phoneNumber pan aadhaar skills status kycStatus averageRating ratingCount') // Select essential fields
        .lean(); // Use .lean() for faster query execution if not modifying documents

        res.json({
            success: true,
            technicians: pendingTechnicians,
            message: "Successfully fetched all pending KYC technicians for Serviceadmin review."
        });
    } catch (error) {
        console.error('Error fetching all pending KYC technicians for Serviceadmin:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch pending KYC technicians.' });
    }
});

// Superadmin: Create Admin User
// Superadmin: Create Admin User
app.post('/api/superadmin/create-admin-user', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { fullName, email, password, role, assignedCities = [], skills = [], sendEmail } = req.body;
    // Removed phoneNumber processing as it's no longer needed for creation
    // const phoneNumber = req.body.phoneNumber ? req.body.phoneNumber.trim() : undefined; 

    try {
        if (!isAnAdminRole(role)) {
            return res.status(400).json({ success: false, message: 'Invalid role specified for admin user creation.' });
        }

        // Removed the check for existing phone number
        // if (phoneNumber) {
        //     const existingUserByPhone = await User.findOne({ phoneNumber: phoneNumber });
        //     if (existingUserByPhone) {
        //         return res.status(409).json({ success: false, message: 'A user with this phone number already exists.' });
        //     }
        // }

        let adminPassword = password;
        if (!adminPassword) {
            // Generate a secure random password if not provided
            adminPassword = crypto.randomBytes(8).toString('base64').slice(0, 12); // 12-char random string
        }

        const newAdmin = new User({
            fullName,
            email,
            password: adminPassword, // Password will be hashed by pre-save hook
            role,
            // Removed phoneNumber from the new User object
            // phoneNumber, 
            assignedCities: role === 'Citymanager' ? assignedCities : [],
            skills: role === 'Serviceadmin' ? skills : [], // Using 'skills' for service admin assigned services
            isVerified: true, // Assuming admin accounts are created verified
            kycStatus: 'approved' // Admins don't have KYC pending
        });
        await newAdmin.save();

        if (sendEmail) {
            const mailOptions = {
                from: EMAIL_USER,
                to: email,
                subject: `TechSeva Admin Account Created - Role: ${role}`,
                html: `
                    <p>Dear ${fullName},</p>
                    <p>Your TechSeva admin account has been created with the role: <strong>${role}</strong>.</p>
                    <p>You can log in at: <a href="http://localhost:${PORT}/admin-login">http://localhost:${PORT}/admin-login</a></p>
                    <p><strong>Your Temporary Password:</strong> ${adminPassword}</p>
                    <p>Please change your password after logging in for the first time.</p>
                    <p>Thank you,</p>
                    <p>TechSeva Team</p>
                `
            };
            transporter.sendMail(mailOptions);
        }

        // Updated success message
        res.status(201).json({ success: true, message: `Admin user (${role}) created successfully! Temporary password sent to email.` });
    } catch (error) {
        console.error('[CREATE ADMIN USER ERROR]:', error);
        if (error.code === 11000) {
            // Only check for email duplicate error, removed phoneNumber check
            if (error.keyPattern && error.keyPattern.email) {
                return res.status(409).json({ success: false, message: 'Email already exists.' });
            }
            // Fallback for other unique index violations if any other unique fields exist
            return res.status(409).json({ success: false, message: 'A duplicate entry was found for a unique field.' });
        }
        res.status(500).json({ success: false, message: 'Failed to create admin user.' });
    }
});

// Update user status (activate/suspend) - for Superadmin, Citymanager, Serviceadmin
app.post('/api/admin/users/:userId/update-status', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin']), async (req, res) => {
    const { userId } = req.params;
    const { status } = req.body; // 'active' or 'suspended'
    const adminRole = req.user.role;

    try {
        const userToUpdate = await User.findById(userId);
        if (!userToUpdate) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Prevent admin from changing their own status
        if (userToUpdate._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ success: false, message: 'You cannot change your own status.' });
        }
        // Superadmin can change anyone's status except self
        // Citymanager can only change status of users/technicians in their assigned cities
        if (adminRole === 'Citymanager') {
            if (!['user', 'technician'].includes(userToUpdate.role)) {
                return res.status(403).json({ success: false, message: 'Citymanager cannot manage other admin roles.' });
            }
            if (userToUpdate.role === 'technician' && (!userToUpdate.workingLocation || !req.user.assignedCities.includes(userToUpdate.workingLocation.city))) {
                 return res.status(403).json({ success: false, message: 'Citymanager can only manage technicians in their assigned cities.' });
            }
            if (userToUpdate.role === 'user' && !req.user.assignedCities.includes(userToUpdate.city)) {
                return res.status(403).json({ success: false, message: 'Citymanager can only manage users in their assigned cities.' });
            }
        }
        // Service Admin can only change status of technicians with their assigned services
        if (adminRole === 'Serviceadmin') {
            if (userToUpdate.role !== 'technician') {
                return res.status(403).json({ success: false, message: 'Service Admin can only manage technicians.' });
            }
            if (!userToUpdate.skills.some(skill => req.user.skills.includes(skill))) {
                 return res.status(403).json({ success: false, message: 'Service Admin can only manage technicians with their assigned services.' });
            }
        }
        // Prevent lower-tier admins from managing Superadmins
        if (userToUpdate.role === 'Superadmin' && adminRole !== 'Superadmin') {
            return res.status(403).json({ success: false, message: 'Only Superadmin can manage other Superadmins.' });
        }

        userToUpdate.status = status;
        await userToUpdate.save();
        res.json({ success: true, message: `User status updated to ${status}.` });
    } catch (error) {
        console.error('[UPDATE USER STATUS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to update user status.' });
    }
});

// Admin reset user password (Superadmin only)
app.post('/api/admin/users/:userId/reset-password', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { userId } = req.params;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (user.googleId && !user.password) { // User registered via Google and has no password
             return res.status(400).json({ success: false, message: 'Cannot reset password for Google-registered accounts without a password set.' });
        }
        if (user._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ success: false, message: 'You cannot reset your own password via this endpoint.' });
        }

        const newPassword = crypto.randomBytes(8).toString('base64').slice(0, 12);
        user.password = newPassword; // Pre-save hook will hash it
        await user.save();

        const mailOptions = {
            from: EMAIL_USER,
            to: user.email,
            subject: 'TechSeva Account Password Reset',
            html: `
                <p>Dear ${user.fullName},</p>
                <p>Your password for the TechSeva account has been reset by an administrator.</p>
                <p><strong>Your New Temporary Password:</strong> ${newPassword}</p>
                <p>Please log in and change your password immediately.</p>
                <p>Thank you,</p>
                <p>TechSeva Team</p>
            `
        };
        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'New password sent to user\'s email.' });
    } catch (error) {
        console.error('[RESET USER PASSWORD ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to reset user password.' });
    }
});

// Get all appliance types (Superadmin, Serviceadmin)
app.get('/api/admin/appliance-types', authenticateToken, authorizeRoles(['Superadmin', 'Serviceadmin']), async (req, res) => {
    try {
        const types = await ApplianceType.find({});
        res.json({ success: true, applianceTypes: types });
    } catch (error) {
        console.error('[GET APPLIANCE TYPES ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch appliance types.' });
    }
});

// Superadmin: Add Appliance Type
app.post('/api/admin/appliance-types', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { name, description, isActive, basePrice, commissionRate } = req.body;
    try {
        const newAppliance = new ApplianceType({ name, description, isActive, basePrice, commissionRate });
        await newAppliance.save();
        res.status(201).json({ success: true, message: 'Appliance type added successfully!', appliance: newAppliance });
    } catch (error) {
        console.error('[ADD APPLIANCE TYPE ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Appliance type with this name already exists.' });
        res.status(500).json({ success: false, message: 'Failed to add appliance type.' });
    }
});

// Superadmin: Update Appliance Type
app.put('/api/admin/appliance-types/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    const { name, description, isActive, basePrice, commissionRate } = req.body;
    try {
        const updatedAppliance = await ApplianceType.findByIdAndUpdate(id, { name, description, isActive, basePrice, commissionRate }, { new: true });
        if (!updatedAppliance) return res.status(404).json({ success: false, message: 'Appliance type not found.' });
        res.json({ success: true, message: 'Appliance type updated successfully!', appliance: updatedAppliance });
    } catch (error) {
        console.error('[UPDATE APPLIANCE TYPE ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Appliance type with this name already exists.' });
        res.status(500).json({ success: false, message: 'Failed to update appliance type.' });
    }
});

// Superadmin: Delete Appliance Type
app.delete('/api/admin/appliance-types/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await ApplianceType.findByIdAndDelete(id);
        res.json({ success: true, message: 'Appliance type deleted successfully!' });
    } catch (error) {
        console.error('[DELETE APPLIANCE TYPE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete appliance type.' });
    }
});

// Get all locations (Superadmin, Citymanager)
app.get('/api/admin/locations', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager']), async (req, res) => {
    try {
        const locations = await Location.find({});
        res.json({ success: true, locations });
    } catch (error) {
        console.error('[GET LOCATIONS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch locations.' });
    }
});

// Superadmin: Add Location
app.post('/api/admin/locations', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { city, state, country, pincodes, status } = req.body;
    try {
        const newLocation = new Location({ city, state, country, pincodes, status });
        await newLocation.save();
        res.status(201).json({ success: true, message: 'Location added successfully!', location: newLocation });
    } catch (error) {
        console.error('[ADD LOCATION ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Location with this city already exists.' });
        res.status(500).json({ success: false, message: 'Failed to add location.' });
    }
});

// Superadmin: Update Location
app.put('/api/admin/locations/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    const { city, state, country, pincodes, status } = req.body;
    try {
        const updatedLocation = await Location.findByIdAndUpdate(id, { city, state, country, pincodes, status }, { new: true });
        if (!updatedLocation) return res.status(404).json({ success: false, message: 'Location not found.' });
        res.json({ success: true, message: 'Location updated successfully!', location: updatedLocation });
    } catch (error) {
        console.error('[UPDATE LOCATION ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Location with this city already exists.' });
        res.status(500).json({ success: false, message: 'Failed to update location.' });
    }
});

// Superadmin: Delete Location
app.delete('/api/admin/locations/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await Location.findByIdAndDelete(id);
        res.json({ success: true, message: 'Location deleted successfully!' });
    } catch (error) {
        console.error('[DELETE LOCATION ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete location.' });
    }
});

// Payments & Pricing Configuration (Superadmin can set base prices and commission rates)
app.post('/api/admin/configure-pricing', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { serviceType, basePrice, commissionRate, region } = req.body; // region concept not fully implemented in schemas
    try {
        const appliance = await ApplianceType.findOne({ name: serviceType });
        if (!appliance) {
            return res.status(404).json({ success: false, message: 'Service type not found.' });
        }
        appliance.basePrice = basePrice !== undefined ? basePrice : appliance.basePrice;
        appliance.commissionRate = commissionRate !== undefined ? commissionRate : appliance.commissionRate;
        
        await appliance.save();

        await FinancialLog.create({
            eventType: 'Pricing Configuration Update',
            relatedId: appliance._id,
            description: `Pricing updated for ${serviceType}. Base Price: ₹${appliance.basePrice.toFixed(2)}, Commission Rate: ${appliance.commissionRate * 100}%. Region: ${region || 'Global'}.`,
            amount: 0 
        });

        res.json({ success: true, message: `Pricing for ${serviceType} updated successfully!` });
    } catch (error) {
        console.error('[CONFIGURE PRICING ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to configure pricing.' });
    }
});

// Get all transactions (for Superadmin and Financeofficer)
app.get('/api/admin/transactions', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    try {
        const transactions = await Transaction.find({});
        res.json({ success: true, transactions });
    } catch (error) {
        console.error('[GET TRANSACTIONS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch transactions.' });
    }
});


// Get all payout requests (Superadmin and Financeofficer)
app.get('/api/admin/payout-requests', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    try {
        // Find transactions of type 'Payout' that are 'Pending'
        const payoutRequests = await Transaction.find({ type: 'Payout', status: 'Pending' })
                                                .populate('userId', 'fullName email phoneNumber balance bankDetails'); // Populate technician data
        res.json({ success: true, payoutRequests });
    } catch (error) {
        console.error('[GET PAYOUT REQUESTS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch payout requests.' });
    }
});

// Process Payout Request (Superadmin and Financeofficer)
app.post('/api/admin/payouts/:transactionId/process', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    const { transactionId } = req.params;
    const { userId, amount } = req.body; // userId and amount from frontend for verification

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const payoutTransaction = await Transaction.findOne({ transactionId: transactionId, type: 'Payout', status: 'Pending' }).session(session);
        if (!payoutTransaction) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'Pending payout request not found or already processed.' });
        }

        const technician = await User.findById(userId).session(session);
        if (!technician || technician.role !== 'technician') {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'Technician not found.' });
        }

        if (payoutTransaction.amount !== amount || payoutTransaction.userId.toString() !== technician._id.toString()) {
            await session.abortTransaction();
            return res.status(400).json({ success: false, message: 'Mismatch in payout details. Please refresh.' });
        }

        if (technician.balance < amount) {
            await session.abortTransaction();
            return res.status(400).json({ success: false, message: 'Technician has insufficient balance for this payout.' });
        }

        // Deduct balance from technician
        technician.balance -= amount;
        payoutTransaction.status = 'Success';
        payoutTransaction.description = `Payout processed for ${technician.fullName} by ${req.user.fullName}.`;
        
        await technician.save({ session });
        await payoutTransaction.save({ session });

        // Log financial event
        await FinancialLog.create([{
            eventType: 'Payout Processed',
            relatedId: payoutTransaction.transactionId,
            description: `Payout of ₹${amount.toFixed(2)} processed for technician ${technician.fullName}. New balance: ₹${technician.balance.toFixed(2)}.`,
            amount: amount,
            status: 'Normal',
            flaggedBy: req.user._id // Log who processed it
        }], { session });

        await session.commitTransaction();
        res.json({ success: true, message: 'Payout processed successfully!' });

    } catch (error) {
        await session.abortTransaction();
        console.error('[PROCESS PAYOUT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to process payout.' });
    } finally {
        session.endSession();
    }
});


// Get all fee recommendations
app.get('/api/admin/fee-recommendations', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    try {
        const recommendations = await FeeRecommendation.find({})
                                                        .populate('recommendedBy', 'fullName role'); // Get recommending admin's details
        res.json({ success: true, recommendations });
    } catch (error) {
        console.error('[GET FEE RECOMMENDATIONS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch fee recommendations.' });
    }
});

// Approve Fee Recommendation (Superadmin)
app.post('/api/admin/fee-recommendations/:id/approve', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        const recommendation = await FeeRecommendation.findById(id);
        if (!recommendation) {
            return res.status(404).json({ success: false, message: 'Fee recommendation not found.' });
        }
        if (recommendation.status !== 'Pending') {
            return res.status(400).json({ success: false, message: 'Recommendation already processed.' });
        }

        // Apply the change (e.g., update ApplianceType's basePrice or commissionRate)
        const appliance = await ApplianceType.findOne({ name: recommendation.serviceType });
        if (appliance) {
            if (recommendation.feeType === 'basePrice') {
                appliance.basePrice = recommendation.newProposedValue;
            } else if (recommendation.feeType === 'commissionRate') {
                appliance.commissionRate = recommendation.newProposedValue;
            }
            await appliance.save();

            recommendation.status = 'Approved';
            await recommendation.save();

            await FinancialLog.create({
                eventType: 'Fee Recommendation Approved',
                relatedId: recommendation._id,
                description: `Fee recommendation for ${recommendation.serviceType} (${recommendation.feeType}) approved by ${req.user.fullName}. Value changed from ₹${recommendation.currentValue} to ₹${recommendation.newProposedValue}.`,
                amount: 0 
            });

            return res.json({ success: true, message: 'Fee recommendation approved and applied!' });
        } else {
            return res.status(404).json({ success: false, message: 'Associated service type not found.' });
        }

    } catch (error) {
        console.error('[APPROVE FEE RECOMMENDATION ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to approve fee recommendation.' });
    }
});

// Reject Fee Recommendation (Superadmin)
app.post('/api/admin/fee-recommendations/:id/reject', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        const recommendation = await FeeRecommendation.findById(id);
        if (!recommendation) {
            return res.status(404).json({ success: false, message: 'Fee recommendation not found.' });
        }
        if (recommendation.status !== 'Pending') {
            return res.status(400).json({ success: false, message: 'Recommendation already processed.' });
        }

        recommendation.status = 'Rejected';
        await recommendation.save();

        await FinancialLog.create({
            eventType: 'Fee Recommendation Rejected',
            relatedId: recommendation._id,
            description: `Fee recommendation for ${recommendation.serviceType} (${recommendation.feeType}) rejected by ${req.user.fullName}.`
        });

        res.json({ success: true, message: 'Fee recommendation rejected.' });
    } catch (error) {
        console.error('[REJECT FEE RECOMMENDATION ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to reject fee recommendation.' });
    }
});

// Issue Tickets Management
app.get('/api/admin/tickets', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin', 'Supportagent']), async (req, res) => {
    try {
        let query = {};
        const userRole = req.user.role;
        const userId = req.user._id;

        // Filter tickets based on admin role
        if (userRole === 'Citymanager' && req.user.assignedCities && req.user.assignedCities.length > 0) {
            const cityUsers = await User.find({ city: { $in: req.user.assignedCities } }).select('_id');
            const cityJobs = await Job.find({ 'location.city': { $in: req.user.assignedCities } }).select('jobId');

            query.$or = [
                { raisedBy: { $in: cityUsers.map(u => u._id) } },
                { jobId: { $in: cityJobs.map(j => j.jobId) } } // Assuming ticket can be linked to jobId
            ];
        } else if (userRole === 'Serviceadmin' && req.user.skills && req.user.skills.length > 0) {
            query.serviceType = { $in: req.user.skills }; // Assuming tickets have a serviceType field
        } 
        // Supportagent or Superadmin see all tickets by default (no additional query filter)

        const tickets = await Ticket.find(query)
            .populate('raisedBy', 'fullName email role') // Ensure fullName and email are populated
            .populate('assignedTo', 'fullName email role')
            .lean(); // Use .lean() for easier modification of plain JS objects

        // Process tickets to handle potentially missing 'raisedBy' users and format output
        const processedTickets = tickets.map(ticket => {
            const raisedByFullName = ticket.raisedBy ? ticket.raisedBy.fullName : 'Unknown User';
            const raisedByEmail = ticket.raisedBy ? ticket.raisedBy.email : 'N/A';
            const raisedByFormatted = `${raisedByFullName} (${raisedByEmail})`; // Desired format: "Name (email)"

            const assignedToFullName = ticket.assignedTo ? ticket.assignedTo.fullName : 'Unassigned';
            const assignedToEmail = ticket.assignedTo ? ticket.assignedTo.email : 'N/A';
            const assignedToFormatted = `${assignedToFullName} (${assignedToEmail})`; // Desired format for assignedTo as well

            return {
                ...ticket, // Keep all original ticket properties
                raisedBy: { // Keep the original populated object for consistency if needed elsewhere
                    _id: ticket.raisedBy ? ticket.raisedBy._id : null,
                    fullName: raisedByFullName,
                    email: raisedByEmail,
                    role: ticket.raisedBy ? ticket.raisedBy.role : 'N/A'
                },
                assignedTo: { // Keep the original populated object for consistency if needed elsewhere
                    _id: ticket.assignedTo ? ticket.assignedTo._id : null,
                    fullName: assignedToFullName,
                    email: assignedToEmail,
                    role: ticket.assignedTo ? ticket.assignedTo.role : 'N/A'
                },
                // Add new fields for the desired formatted display in the frontend
                raisedByDisplay: raisedByFormatted,
                assignedToDisplay: assignedToFormatted
            };
        });

        console.log(`[GET TICKETS API] Found ${processedTickets.length} tickets.`);
        res.json({ success: true, tickets: processedTickets });
    } catch (error) {
        console.error('[GET TICKETS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch tickets.' });
    }
});
// Centralized function to process and save payment details
const processAndSavePayment = async ({ jobId, totalAmount, paymentMethod, paymentDetails }) => {
    try {
        const job = await Job.findOne({ jobId: jobId });

        if (!job) {
            return { success: false, message: 'Job not found.' };
        }

        // Check if the job status allows payment, unless it's a warranty claim
        if (job.status !== 'Diagnosed' && job.status !== 'Completed' && !job.isWarrantyClaim) {
             return { success: false, message: `Payment can only be processed for jobs that are 'Diagnosed' or 'Completed'. Current status: ${job.status}.` };
        }
        
        // Handle the case where a warranty claim has a zero totalAmount
        if (job.isWarrantyClaim && totalAmount === 0 && paymentMethod === 'COD') {
            console.log(`[PROCESS PAYMENT] Warranty claim for job ${jobId} has zero total. Skipping payment processing.`);
            job.status = 'Paid'; // Mark as paid to complete the flow
            await job.save();
            return { success: true, message: 'Warranty job confirmed. No payment needed from customer.' };
        }


        job.payment = {
            amount: parseFloat(totalAmount),
            method: paymentMethod,
            details: paymentDetails,
            status: 'Paid',
            paidAt: new Date(),
            transactionId: paymentDetails.transactionId
        };
        job.status = 'Paid';

        await job.save();

        // Create a PaymentIn transaction record
        await Transaction.create({
            transactionId: `TXN-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
            userId: job.userId,
            relatedUserId: job.assignedTechnicianId,
            jobId: job.jobId,
            type: 'PaymentIn',
            amount: job.payment.amount,
            status: 'Success',
            paymentMethod: job.payment.method,
            description: `Customer payment for Job ${job.jobId}`
        });

        // Calculate and update technician balance
        if (job.assignedTechnicianId && job.quotation && job.quotation.totalEstimate !== undefined) {
            // Check if it's a warranty claim
            if (job.isWarrantyClaim) {
                // Technician's earning is the full quotation, paid by the app
                const technicianPayoutFromApp = (job.quotation.partCost || 0) + (job.quotation.laborCost || 0) + (job.quotation.travelCharges || 0);
                
                if (technicianPayoutFromApp > 0) {
                     await User.findByIdAndUpdate(
                        job.assignedTechnicianId,
                        { $inc: { balance: technicianPayoutFromApp, jobsCompleted: 1 } },
                        { new: true }
                    );
                    await Transaction.create({
                        transactionId: `TXNE-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
                        userId: job.assignedTechnicianId,
                        relatedUserId: job.userId,
                        jobId: job.jobId,
                        type: 'Earning (Warranty)',
                        amount: technicianPayoutFromApp,
                        status: 'Success',
                        description: `Technician earning for Warranty Job ${job.jobId} (Paid by App)`
                    });
                }
            } else {
                // Normal job earning calculation
                const grossAmount = job.quotation.totalEstimate;
                const appCommission = grossAmount * APP_COMMISSION_RATE;
                const amountBeforeTax = grossAmount - appCommission;
                const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
                const technicianNetEarning = amountBeforeTax - technicianTaxDeduction;

                if (technicianNetEarning > 0) {
                    await User.findByIdAndUpdate(
                        job.assignedTechnicianId,
                        { $inc: { balance: technicianNetEarning, jobsCompleted: 1 } },
                        { new: true }
                    );
                    await Transaction.create({
                        transactionId: `TXNE-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
                        userId: job.assignedTechnicianId,
                        relatedUserId: job.userId,
                        jobId: job.jobId,
                        type: 'Earning',
                        amount: technicianNetEarning,
                        status: 'Success',
                        description: `Technician earning for Job ${job.jobId}`
                    });
                    await Transaction.create({
                        transactionId: `TXNC-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,
                        userId: job.assignedTechnicianId,
                        relatedUserId: job.userId,
                        jobId: job.jobId,
                        type: 'Commission',
                        amount: appCommission,
                        status: 'Success',
                        description: `Platform commission from Job ${job.jobId}`
                    });
                }
            }
        }
        
        return { success: true, message: 'Payment processed successfully and job marked as Paid!', job: job.toJSON() };

    } catch (err) {
        console.error('[PROCESS & SAVE PAYMENT ERROR]:', err);
        return { success: false, message: 'Internal server error during payment processing.' };
    }
};

// UPDATED: Main endpoint that uses the helper function
app.post('/api/process-payment', authenticateToken, authorizeRoles(['user', 'Superadmin', 'Financeofficer']), async (req, res) => {
    console.log('[PROCESS PAYMENT API] Request received for job ID:', req.body.jobId, 'by user:', req.user._id);
    const { jobId, totalAmount, paymentMethod, paymentDetails } = req.body;
    
    // Check if the current user has permission (job owner, superadmin, or finance officer)
    const job = await Job.findOne({ jobId: jobId });
    if (!job) {
        return res.status(404).json({ success: false, message: 'Job not found.' });
    }
    const jobUserIdStr = job.userId ? job.userId.toString() : null;
    if (jobUserIdStr !== req.user._id.toString() && !['Superadmin', 'Financeofficer'].includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Access denied to process payment for this job.' });
    }
    if (!totalAmount || isNaN(totalAmount) || totalAmount < 0 || !paymentMethod) { 
        return res.status(400).json({ success: false, message: 'Total amount and payment method are required.' });
    }
    
    // Call the centralized processing function
    const result = await processAndSavePayment({
        jobId,
        totalAmount,
        paymentMethod,
        paymentDetails
    });

    if (result.success) {
        res.json({ success: true, message: result.message, job: result.job });
    } else {
        res.status(500).json({ success: false, message: result.message });
    }
});

// Admin: Assign Ticket
app.post('/api/admin/tickets/:ticketId/assign', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin', 'Supportagent']), async (req, res) => {
    const { ticketId } = req.params;
    const { assignedTo } = req.body; // Can be an admin user ID
    try {
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found.' });
        }

        const assignee = await User.findById(assignedTo);
        if (!assignee || !isAnAdminRole(assignee.role)) { // Ensure assignee is an admin role
            return res.status(400).json({ success: false, message: 'Invalid assignee: User not found or not an admin role.' });
        }

        ticket.assignedTo = assignee._id;
        ticket.status = 'In Progress'; // Automatically set status when assigned
        ticket.lastUpdate = new Date();
        await ticket.save();
        res.json({ success: true, message: `Ticket ${ticketId} assigned to ${assignee.fullName}.` });
    } catch (error) {
        console.error('[ASSIGN TICKET ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to assign ticket.' });
    }
});

// Admin: Resolve Ticket
app.post('/api/admin/tickets/:ticketId/resolve', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin', 'Supportagent']), async (req, res) => {
    const { ticketId } = req.params;
    try {
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found.' });
        }
        ticket.status = 'Resolved';
        ticket.lastUpdate = new Date();
        await ticket.save();
        res.json({ success: true, message: `Ticket ${ticketId} marked as resolved.` });
    } catch (error) {
        console.error('[RESOLVE TICKET ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to resolve ticket.' });
    }
});

// Superadmin: Close Ticket
app.post('/api/admin/tickets/:ticketId/close', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { ticketId } = req.params;
    try {
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found.' });
        }
        ticket.status = 'Closed';
        ticket.lastUpdate = new Date();
        await ticket.save();
        res.json({ success: true, message: `Ticket ${ticketId} marked as closed.` });
    } catch (error) {
        console.error('[CLOSE TICKET ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to close ticket.' });
    }
});


// In-App Announcements (Superadmin only for creation/modification, others can view via separate endpoint if needed)
app.get('/api/admin/announcements', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const announcements = await Announcement.find({}).sort({ publishedOn: -1 });
        res.json({ success: true, announcements });
    } catch (error) {
        console.error('[GET ANNOUNCEMENTS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch announcements.' });
    }
});

app.post('/api/admin/announcements', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { title, content, targetAudience } = req.body;
    try {
        const newAnnouncement = new Announcement({ title, content, targetAudience, createdBy: req.user._id });
        await newAnnouncement.save();
        res.status(201).json({ success: true, message: 'Announcement published successfully!', announcement: newAnnouncement });
    } catch (error) {
        console.error('[CREATE ANNOUNCEMENT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to publish announcement.' });
    }
});

app.put('/api/admin/announcements/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    const { title, content, targetAudience } = req.body;
    try {
        const updatedAnnouncement = await Announcement.findByIdAndUpdate(id, { title, content, targetAudience }, { new: true });
        if (!updatedAnnouncement) return res.status(404).json({ success: false, message: 'Announcement not found.' });
        res.json({ success: true, message: 'Announcement updated successfully!', announcement: updatedAnnouncement });
    } catch (error) {
        console.error('[UPDATE ANNOUNCEMENT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to update announcement.' });
    }
});

app.delete('/api/admin/announcements/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await Announcement.findByIdAndDelete(id);
        res.json({ success: true, message: 'Announcement deleted successfully!' });
    } catch (error) {
        console.error('[DELETE ANNOUNCEMENT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete announcement.' });
    }
});


// Coupons & Promotions (Superadmin manages, others suggest)
app.get('/api/admin/promotions', authenticateToken, authorizeRoles(['Superadmin', 'Citymanager', 'Serviceadmin', 'Financeofficer', 'Supportagent']), async (req, res) => {
    try {
        let query = {};
        const userRole = req.user.role;

        // Citymanager can only view promotions relevant to their assigned cities
        if (userRole === 'Citymanager' && req.user.assignedCities && req.user.assignedCities.length > 0) {
            query.$or = [
                { targetAudience: 'All' },
                { targetAudience: { $in: req.user.assignedCities } },
                { suggestedCities: { $in: req.user.assignedCities } } // Include promotions they suggested
            ];
        } 
        // Serviceadmin can only view promotions relevant to their assigned services
        else if (userRole === 'Serviceadmin' && req.user.skills && req.user.skills.length > 0) {
            query.$or = [
                { targetAudience: 'All' },
                { targetAudience: { $in: req.user.skills } },
                { targetServices: { $in: req.user.skills } } // Include promotions they suggested
            ];
        }
        // Other admin roles (Superadmin, Financeofficer, Supportagent) see all promotions by default

        const promotions = await Promotion.find(query).sort({ expiryDate: 1 });
        res.json({ success: true, promotions });
    } catch (error) {
        console.error('[GET PROMOTIONS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch promotions.' });
    }
});

app.post('/api/admin/promotions', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate, targetAudience, usageLimit, totalUsageLimit } = req.body;
    try {
        const newPromotion = new Promotion({
            couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate, targetAudience,
            usageLimit, totalUsageLimit,
            status: 'Active', // Superadmin directly creates active coupons
            suggestedBy: req.user._id
        });
        await newPromotion.save();
        res.status(201).json({ success: true, message: 'Coupon created successfully!', promotion: newPromotion });
    } catch (error) {
        console.error('[CREATE PROMOTION ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Coupon code already exists.' });
        res.status(500).json({ success: false, message: 'Failed to create coupon.' });
    }
});

app.put('/api/admin/promotions/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    const { couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate, targetAudience, usageLimit, totalUsageLimit, status } = req.body;
    try {
        const updatedPromotion = await Promotion.findByIdAndUpdate(id, {
            couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate, targetAudience,
            usageLimit, totalUsageLimit, status
        }, { new: true });
        if (!updatedPromotion) return res.status(404).json({ success: false, message: 'Coupon not found.' });
        res.json({ success: true, message: 'Coupon updated successfully!', promotion: updatedPromotion });
    } catch (error) {
        console.error('[UPDATE PROMOTION ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Coupon code already exists.' });
        res.status(500).json({ success: false, message: 'Failed to update coupon.' });
    }
});

app.post('/api/admin/promotions/:id/approve', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        const promotion = await Promotion.findById(id);
        if (!promotion) return res.status(404).json({ success: false, message: 'Coupon not found.' });
        promotion.status = 'Active';
        await promotion.save();
        res.json({ success: true, message: 'Coupon approved and activated!' });
    } catch (error) {
        console.error('[APPROVE COUPON ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to approve coupon.' });
    }
});

app.post('/api/admin/promotions/:id/reject', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        const promotion = await Promotion.findById(id);
        if (!promotion) return res.status(404).json({ success: false, message: 'Coupon not found.' });
        promotion.status = 'Rejected';
        await promotion.save();
        res.json({ success: true, message: 'Coupon rejected.' });
    } catch (error) {
        console.error('[REJECT COUPON ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to reject coupon.' });
    }
});

app.delete('/api/admin/promotions/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await Promotion.findByIdAndDelete(id);
        res.json({ success: true, message: 'Coupon deleted successfully!' });
    } catch (error) {
        console.error('[DELETE PROMOTION ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete coupon.' });
    }
});


// Contact Messages (Superadmin, Supportagent can view and Superadmin can delete)
app.get('/api/admin/contact-messages', authenticateToken, authorizeRoles(['Superadmin', 'Supportagent']), async (req, res) => {
    try {
        const messages = await ContactMessage.find({}).sort({ createdAt: -1 });
        res.json({ success: true, messages });
    } catch (error) {
        console.error('[GET CONTACT MESSAGES ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch contact messages.' });
    }
});

app.delete('/api/admin/contact-messages/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await ContactMessage.findByIdAndDelete(id);
        res.json({ success: true, message: 'Contact message deleted successfully!' });
    } catch (error) {
        console.error('[DELETE CONTACT MESSAGE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete contact message.' });
    }
});

// Financial Compliance Logs (Superadmin and Financeofficer)
app.get('/api/admin/compliance-logs', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    try {
        const logs = await FinancialLog.find({}).sort({ timestamp: -1 });
        res.json({ success: true, logs });
    } catch (error) {
        console.error('[GET COMPLIANCE LOGS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch compliance logs.' });
    }
});

app.post('/api/admin/compliance-logs/:id/flag', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    try {
        const log = await FinancialLog.findById(id);
        if (!log) return res.status(404).json({ success: false, message: 'Log not found.' });
        log.status = 'Flagged';
        log.reasonFlagged = reason;
        log.flaggedBy = req.user._id;
        await log.save();
        res.json({ success: true, message: 'Log flagged successfully!' });
    } catch (error) {
        console.error('[FLAG LOG ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to flag log.' });
    }
});

app.post('/api/admin/compliance-logs/:id/unflag', authenticateToken, authorizeRoles(['Superadmin', 'Financeofficer']), async (req, res) => {
    const { id } = req.params;
    try {
        const log = await FinancialLog.findById(id);
        if (!log) return res.status(404).json({ success: false, message: 'Log not found.' });
        log.status = 'Normal';
        log.reasonFlagged = undefined;
        log.flaggedBy = undefined;
        await log.save();
        res.json({ success: true, message: 'Log unflagged successfully!' });
    } catch (error) {
        console.error('[UNFLAG LOG ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to unflag log.' });
    }
});

app.delete('/api/admin/compliance-logs/:id', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    const { id } = req.params;
    try {
        await FinancialLog.findByIdAndDelete(id);
        res.json({ success: true, message: 'Compliance log deleted successfully!' });
    } catch (error) {
        console.error('[DELETE COMPLIANCE LOG ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to delete compliance log.' });
    }
});


// --- Citymanager Specific API Endpoints ---
app.get('/api/citymanager/dashboard-overview', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const endOfToday = new Date();
        endOfToday.setHours(23, 59, 59, 999);

        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay()); // Sunday as start of week
        startOfWeek.setHours(0, 0, 0, 0);

        const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

        // Filter jobs by assigned cities
        const jobsInCities = await Job.find({ 'location.city': { $in: cityManager.assignedCities } });

        const dailyBookings = jobsInCities.filter(job => job.createdAt >= today && job.createdAt <= endOfToday).length;
        const weeklyBookings = jobsInCities.filter(job => job.createdAt >= startOfWeek).length;

        // Simplified monthly earnings for Citymanager: sum of paid job total estimates
        const monthlyEarningsJobs = jobsInCities.filter(job => job.payment && job.payment.status === 'Paid' && job.payment.paidAt >= startOfMonth);
        const monthlyEarnings = monthlyEarningsJobs.reduce((sum, job) => sum + (job.payment.amount || 0), 0);

        const techniciansInCities = await User.find({ role: 'technician', 'workingLocation.city': { $in: cityManager.assignedCities } });
        const activeTechnicians = techniciansInCities.filter(tech => tech.status === 'active').length;
        const pendingKycApprovals = techniciansInCities.filter(tech => tech.kycStatus === 'pending').length;

        const usersInCities = await User.find({ city: { $in: cityManager.assignedCities } }).select('_id');
        const ticketsInCities = await Ticket.find({ raisedBy: { $in: usersInCities.map(u => u._id) } });
        const openTickets = ticketsInCities.filter(ticket => ticket.status === 'Open' || ticket.status === 'In Progress' || ticket.status === 'Escalated').length;

        res.json({
            success: true,
            data: {
                dailyBookings,
                weeklyBookings,
                monthlyEarnings: parseFloat(monthlyEarnings.toFixed(2)),
                activeTechnicians,
                pendingKycApprovals,
                openTickets
            }
        });

    } catch (error) {
        console.error('[Citymanager DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Citymanager: Suggest Coupon
app.post('/api/citymanager/promotions/suggest', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    const { couponCode, discountType, discountValue, minOrderAmount, expiryDate, maxDiscount } = req.body; // Added maxDiscount
    try {
        const cityManager = req.user;
        const newPromotion = new Promotion({
            couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate,
            targetAudience: [], // Leave empty, specific cities are in suggestedCities
            status: 'Pending', // Needs Superadmin approval
            suggestedBy: cityManager._id,
            suggestedCities: cityManager.assignedCities // Record which cities suggested this
        });
        await newPromotion.save();
        res.status(201).json({ success: true, message: 'Coupon suggestion submitted for approval!' });
    } catch (error) {
        console.error('[Citymanager SUGGEST COUPON ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Coupon code already exists.' });
        res.status(500).json({ success: false, message: 'Failed to submit coupon suggestion.' });
    }
});

// Citymanager: Send Notifications to users/providers in assigned cities
app.post('/api/citymanager/notifications/send', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    const { title, content, targetAudience = ['All'] } = req.body; // targetAudience can be ['All'], ['user'], ['technician']
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager to send notifications.' });
        }
        
        // Combine explicitly targeted audiences with the Citymanager's assigned cities
        const finalTargetAudience = [...new Set([...targetAudience, ...cityManager.assignedCities])]; // Use Set for unique values
        
        const newAnnouncement = new Announcement({
            title: title,
            content: content,
            targetAudience: finalTargetAudience, 
            createdBy: cityManager._id
        });
        await newAnnouncement.save();
        res.status(201).json({ success: true, message: 'Notification sent successfully to assigned cities!' });
    } catch (error) {
        console.error('[Citymanager SEND NOTIFICATION ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to send notification.' });
    }
});

// Citymanager: Export Earnings Report (CSV)
app.get('/api/citymanager/reports/earnings', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const paidJobs = await Job.find({
            'location.city': { $in: cityManager.assignedCities },
            'payment.status': 'Paid'
        }).populate('userId', 'fullName').populate('assignedTechnicianId', 'fullName');

        if (paidJobs.length === 0) {
            return res.status(404).json({ success: false, message: 'No paid jobs found for your assigned cities to generate report.' });
        }

        const records = paidJobs.map(job => {
            const grossAmount = job.quotation ? job.quotation.totalEstimate : 0;
            const appCommission = grossAmount * APP_COMMISSION_RATE;
            const amountBeforeTax = grossAmount - appCommission;
            const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
            const netEarning = amountBeforeTax - technicianTaxDeduction;

            return {
                jobId: job.jobId,
                customerName: job.userId ? job.userId.fullName : 'N/A',
                technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'N/A',
                serviceType: job.applianceType,
                grossAmountPaid: grossAmount.toFixed(2),
                appCommission: appCommission.toFixed(2),
                technicianTaxDeduction: technicianTaxDeduction.toFixed(2),
                netEarningTechnician: netEarning.toFixed(2),
                paidDate: job.payment.paidAt ? new Date(job.payment.paidAt).toLocaleDateString() : 'N/A'
            };
        });

        const filePath = path.join(__dirname, 'city_earnings_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath, 
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'customerName', title: 'Customer Name' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'grossAmountPaid', title: 'Gross Amount Paid (₹)' },
                { id: 'appCommission', title: 'App Commission (₹)' },
                { id: 'technicianTaxDeduction', title: 'Tax Deduction (₹)' },
                { id: 'netEarningTechnician', title: 'Net Earning (Technician) (₹)' },
                { id: 'paidDate', title: 'Paid Date' }
            ]
        });

        await csvWriter.writeRecords(records); // Returns a promise
        res.download(filePath, 'city_earnings_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { // Try to delete even if send fails
                    if (unlinkErr) console.error('Error deleting CSV file after send error:', unlinkErr);
                });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { // Delete file after send
                    if (unlinkErr) console.error('Error deleting CSV file after successful send:', unlinkErr);
                });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT EARNINGS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export earnings report.' });
    }
});

// Citymanager: Export Service Performance Report (CSV)
app.get('/api/citymanager/reports/service-performance', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const jobs = await Job.find({
            'location.city': { $in: cityManager.assignedCities },
            status: { $in: ['Completed', 'Cancelled'] } // Consider completed and cancelled jobs for performance
        }).populate('assignedTechnicianId', 'fullName email averageRating');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            serviceType: job.applianceType,
            status: job.status,
            city: job.location ? job.location.city : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Unassigned',
            technicianRating: job.assignedTechnicianId ? job.assignedTechnicianId.averageRating : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleDateString() : 'N/A',
            completedDate: job.updatedAt ? new Date(job.updatedAt).toLocaleDateString() : 'N/A' // Assuming update time for completion/cancellation
        }));

        const filePath = path.join(__dirname, 'city_service_performance_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'status', title: 'Status' },
                { id: 'city', title: 'City' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianRating', title: 'Technician Rating' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'completedDate', title: 'Completed/Cancelled Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'city_service_performance_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                 fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT SERVICE PERFORMANCE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export service performance report.' });
    }
});

// Citymanager: Export Complaints Report (CSV)
app.get('/api/citymanager/reports/complaints', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const userIdsInCities = await User.find({ city: { $in: cityManager.assignedCities } }).select('_id');
        const tickets = await Ticket.find({ raisedBy: { $in: userIdsInCities.map(u => u._id) } })
                                    .populate('raisedBy', 'fullName email')
                                    .populate('assignedTo', 'fullName email');

        const records = tickets.map(ticket => ({
            ticketId: ticket.ticketId,
            raisedBy: ticket.raisedBy ? ticket.raisedBy.fullName : 'N/A',
            raisedByEmail: ticket.raisedBy ? ticket.raisedBy.email : 'N/A',
            subject: ticket.subject,
            description: ticket.description,
            status: ticket.status,
            priority: ticket.priority,
            assignedTo: ticket.assignedTo ? ticket.assignedTo.fullName : 'Unassigned',
            lastUpdate: new Date(ticket.lastUpdate).toLocaleString()
        }));

        const filePath = path.join(__dirname, 'city_complaints_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'ticketId', title: 'Ticket ID' },
                { id: 'raisedBy', title: 'Raised By' },
                { id: 'raisedByEmail', title: 'Raised By Email' },
                { id: 'subject', title: 'Subject' },
                { id: 'description', title: 'Description' },
                { id: 'status', title: 'Status' },
                { id: 'priority', title: 'Priority' },
                { id: 'assignedTo', title: 'Assigned To' },
                { id: 'lastUpdate', title: 'Last Update' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'city_complaints_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT COMPLAINTS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export complaints report.' });
    }
});


// --- Service Admin Specific API Endpoints ---
app.get('/api/serviceadmin/dashboard-overview', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const serviceAdmin = req.user;
        if (!serviceAdmin.skills || serviceAdmin.skills.length === 0) {
            return res.status(400).json({ success: false, message: 'No services assigned to this Service Admin.' });
        }

        const techniciansInServices = await User.find({
            role: 'technician',
            skills: { $in: serviceAdmin.skills }
        });
        const totalProviders = techniciansInServices.length;
        const activeProviders = techniciansInServices.filter(tech => tech.status === 'active').length;
        const pendingKycApprovals = techniciansInServices.filter(tech => tech.kycStatus === 'pending').length;

        const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const completedJobsThisMonth = await Job.countDocuments({
            applianceType: { $in: serviceAdmin.skills },
            status: 'Completed',
            createdAt: { $gte: startOfMonth }
        });

        const openTickets = await Ticket.countDocuments({
            serviceType: { $in: serviceAdmin.skills },
            status: { $in: ['Open', 'In Progress', 'Escalated'] }
        });

        res.json({
            success: true,
            data: {
                totalProviders,
                activeProviders,
                pendingKycApprovals,
                completedJobsThisMonth,
                openTickets
            }
        });

    } catch (error) {
        console.error('[SERVICE ADMIN DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Service Admin: Suggest Service-Specific Coupon
app.post('/api/serviceadmin/promotions/suggest', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    const { couponCode, discountType, discountValue, minOrderAmount, expiryDate, maxDiscount } = req.body; 
    try {
        const serviceAdmin = req.user;
        const newPromotion = new Promotion({
            couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate,
            targetAudience: [], // Set dynamically based on targetServices
            status: 'Pending', // Needs Superadmin approval
            suggestedBy: serviceAdmin._id,
            targetServices: serviceAdmin.skills // Record which services suggested this
        });
        await newPromotion.save();
        res.status(201).json({ success: true, message: 'Coupon suggestion submitted for approval!' });
    } catch (error) {
        console.error('[SERVICE ADMIN SUGGEST COUPON ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Coupon code already exists.' });
        res.status(500).json({ success: false, message: 'Failed to submit coupon suggestion.' });
    }
});

// Service Admin: Suggest Fee Change to Superadmin/Finance
app.post('/api/serviceadmin/fee-recommendations/suggest', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    const { serviceType, feeType, newProposedValue, reason } = req.body;
    try {
        const serviceAdmin = req.user;

        // Ensure the serviceType is one of the admin's assigned skills
        if (!serviceAdmin.skills.includes(serviceType)) {
            return res.status(403).json({ success: false, message: `You are not authorized to suggest fee changes for service type: ${serviceType}.` });
        }

        // Fetch current value for context
        const appliance = await ApplianceType.findOne({ name: serviceType });
        let currentValue = 0;
        if (appliance) {
            if (feeType === 'basePrice') currentValue = appliance.basePrice;
            else if (feeType === 'commissionRate') currentValue = appliance.commissionRate;
            else return res.status(400).json({ success: false, message: 'Invalid fee type specified.' });
        } else {
            return res.status(404).json({ success: false, message: 'Service type not found for current value lookup.' });
        }

        const newRecommendation = new FeeRecommendation({
            serviceType,
            feeType,
            currentValue,
            newProposedValue,
            reason,
            recommendedBy: serviceAdmin._id,
            adminRole: serviceAdmin.role,
            status: 'Pending'
        });
        await newRecommendation.save();
        res.status(201).json({ success: true, message: 'Fee change recommendation submitted for approval!' });
    } catch (error) {
        console.error('[SERVICE ADMIN SUGGEST FEE CHANGE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to submit fee change recommendation.' });
    }
});

// Service Admin: Export Service Performance Report (CSV)
app.get('/api/serviceadmin/reports/service-performance', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const serviceAdmin = req.user;
        if (!serviceAdmin.skills || serviceAdmin.skills.length === 0) {
            return res.status(400).json({ success: false, message: 'No services assigned to this Service Admin.' });
        }

        const jobs = await Job.find({
            applianceType: { $in: serviceAdmin.skills },
            status: { $in: ['Completed', 'Cancelled'] } 
        }).populate('assignedTechnicianId', 'fullName email averageRating');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            serviceType: job.applianceType,
            status: job.status,
            city: job.location ? job.location.city : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Unassigned',
            technicianRating: job.assignedTechnicianId ? job.assignedTechnicianId.averageRating : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleDateString() : 'N/A',
            completedDate: job.updatedAt ? new Date(job.updatedAt).toLocaleDateString() : 'N/A'
        }));

        const filePath = path.join(__dirname, 'service_admin_performance_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'status', title: 'Status' },
                { id: 'city', title: 'City' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianRating', title: 'Technician Rating' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'completedDate', title: 'Completed/Cancelled Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'service_admin_performance_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[SERVICE ADMIN EXPORT SERVICE PERFORMANCE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export service performance report.' });
    }
});


// --- Finance Officer Specific API Endpoints ---
app.get('/api/finance/dashboard-overview', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const endOfToday = new Date();
        endOfToday.setHours(23, 59, 59, 999);

        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay());
        startOfWeek.setHours(0, 0, 0, 0);

        const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

        const dailyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: today, $lte: endOfToday } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const weeklyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: startOfWeek } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const monthlyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: startOfMonth } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const pendingPayouts = (await Transaction.aggregate([
            { $match: { type: 'Payout', status: 'Pending' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const failedTransactions = await Transaction.countDocuments({ status: 'Failed' });

        res.json({
            success: true,
            data: {
                dailyEarnings: parseFloat(dailyEarnings.toFixed(2)),
                weeklyEarnings: parseFloat(weeklyEarnings.toFixed(2)),
                monthlyEarnings: parseFloat(monthlyEarnings.toFixed(2)),
                pendingPayouts: parseFloat(pendingPayouts.toFixed(2)),
                failedTransactions
            }
        });

    } catch (error) {
        console.error('[FINANCE DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Finance Officer: Get promotions impact (read-only)
app.get('/api/finance/promotions-impact', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    try {
        const promotions = await Promotion.find({}); // Get all promotions
        // In a real system, you'd calculate total discounted amount from Job.payment if coupon was used
        // For now, usageCount is assumed to be tracked.
        res.json({ success: true, promotions });
    } catch (error) {
        console.error('[FINANCE GET PROMOTIONS IMPACT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch promotions impact data.' });
    }
});


// Finance Officer: Get revenue reports by filters
app.get('/api/finance/reports/revenue', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    const { period, city, service, format } = req.query; // 'daily', 'weekly', 'monthly', 'yearly', 'csv'
    try {
        let matchStage = { 'payment.status': 'Paid' };

        // Apply date filtering
        const today = new Date();
        if (period === 'daily') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), today.getMonth(), today.getDate()), $lte: new Date(today.getFullYear(), today.getMonth(), today.getDate(), 23, 59, 59, 999) };
        } else if (period === 'weekly') {
            const startOfWeek = new Date(today.getFullYear(), today.getMonth(), today.getDate() - today.getDay());
            matchStage['payment.paidAt'] = { $gte: startOfWeek, $lte: new Date(startOfWeek.getFullYear(), startOfWeek.getMonth(), startOfWeek.getDate() + 6, 23, 59, 59, 999) };
        } else if (period === 'monthly') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), today.getMonth(), 1), $lte: new Date(today.getFullYear(), today.getMonth() + 1, 0, 23, 59, 59, 999) };
        } else if (period === 'yearly') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), 0, 1), $lte: new Date(today.getFullYear(), 11, 31, 23, 59, 59, 999) };
        }

        // Apply city and service filters
        if (city) {
            matchStage['location.city'] = city;
        }
        if (service) {
            matchStage['applianceType'] = service;
        }

        const reportData = await Job.aggregate([
            { $match: matchStage },
            { $project: {
                grossAmount: '$payment.amount',
                appCommission: { $multiply: ['$payment.amount', APP_COMMISSION_RATE] }
            }},
            { $group: {
                _id: null,
                totalGrossRevenue: { $sum: '$grossAmount' },
                totalCommissionsEarned: { $sum: '$appCommission' },
                // Total payouts and refunds would typically come from Transaction collection,
                // but for simplicity, we'll initialize them to 0 here if not explicitly joined/calculated
                totalPayoutsMade: { $sum: 0 }, 
                totalRefunds: { $sum: 0 } 
            }}
        ]);

        let result = {
            grossRevenue: 0,
            commissionsEarned: 0,
            netRevenue: 0,
            payoutsMade: 0,
            refunds: 0
        };

        if (reportData.length > 0) {
            result.grossRevenue = reportData[0].totalGrossRevenue;
            result.commissionsEarned = reportData[0].totalCommissionsEarned;
            result.netRevenue = result.grossRevenue - result.payoutsMade - result.refunds; // Simplified calculation
        }

        if (format === 'csv') {
            const csvRecords = [{
                'Period': period || 'Overall',
                'City': city || 'All',
                'Service': service || 'All',
                'Gross Revenue (₹)': result.grossRevenue.toFixed(2),
                'Commissions Earned (₹)': result.commissionsEarned.toFixed(2),
                'Net Revenue (₹)': result.netRevenue.toFixed(2),
                'Payouts Made (₹)': result.payoutsMade.toFixed(2),
                'Refunds (₹)': result.refunds.toFixed(2)
            }];

            const filePath = path.join(__dirname, 'finance_revenue_report.csv');
            const csvWriter = createObjectCsvWriter({
                path: filePath,
                header: [
                    { id: 'Period', title: 'Period' },
                    { id: 'City', title: 'City' },
                    { id: 'Service', title: 'Service' },
                    { id: 'Gross Revenue (₹)', title: 'Gross Revenue (₹)' },
                    { id: 'Commissions Earned (₹)', title: 'Commissions Earned (₹)' },
                    { id: 'Net Revenue (₹)', title: 'Net Revenue (₹)' },
                    { id: 'Payouts Made (₹)', title: 'Payouts Made (₹)' },
                    { id: 'Refunds (₹)', title: 'Refunds (₹)' }
                ]
            });

            await csvWriter.writeRecords(csvRecords);
            res.download(filePath, `revenue_report_${period || 'overall'}_${city || 'all'}_${service || 'all'}.csv`, (err) => {
                if (err) {
                    console.error('Error downloading CSV:', err);
                    fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                    res.status(500).json({ success: false, message: 'Error downloading file.' });
                } else {
                    fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                }
            });

        } else {
            // Return JSON for display in panel
            res.json({ success: true, reportData: [{
                periodLabel: period, // For simple display
                grossRevenue: result.grossRevenue,
                netRevenue: result.netRevenue,
                commissionsEarned: result.commissionsEarned,
                payoutsMade: result.payoutsMade,
                refunds: result.refunds
            }] });
        }

    } catch (error) {
        console.error('[FINANCE REVENUE REPORT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to generate revenue report.' });
    }
});


// --- Support Agent Specific API Endpoints ---
app.get('/api/support/dashboard-overview', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    try {
        const openTickets = await Ticket.countDocuments({ status: 'Open' });
        const inProgressTickets = await Ticket.countDocuments({ status: 'In Progress' });
        const resolvedToday = await Ticket.countDocuments({
            status: 'Resolved',
            lastUpdate: { $gte: new Date().setHours(0, 0, 0, 0), $lte: new Date().setHours(23, 59, 59, 999) }
        });
        const totalTickets = await Ticket.countDocuments({});

        res.json({
            success: true,
            data: {
                openTickets,
                inProgressTickets,
                resolvedToday,
                totalTickets
            }
        });
    } catch (error) {
        console.error('[SUPPORT DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Support Agent: Profile lookup by email
app.get('/api/support/lookup-profile', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required for lookup.' });
    }
    try {
        const user = await User.findOne({ email }).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User or provider not found.' });
        }
        res.json({ success: true, user });
    } catch (error) {
        console.error('[LOOKUP PROFILE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to lookup profile.' });
    }
});

// Support Agent: Escalate Ticket
app.post('/api/support/tickets/:ticketId/escalate', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    const { ticketId } = req.params;
    const { reason } = req.body;
    try {
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found.' });
        }
        ticket.status = 'Escalated';
        ticket.escalationReason = reason;
        ticket.lastUpdate = new Date();
        // Optionally, assign to Superadmin or a specific "escalation" role
        // For simplicity, we just mark as escalated. Superadmin will see it.
        await ticket.save();
        res.json({ success: true, message: `Ticket ${ticketId} escalated successfully!` });
    } catch (error) {
        console.error('[ESCALATE TICKET ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to escalate ticket.' });
    }
});


// --- General Reports Export Endpoints (Superadmin) ---

app.get('/api/reports/users', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        const records = users.map(user => ({
            fullName: user.fullName,
            email: user.email,
            phoneNumber: user.phoneNumber || 'N/A',
            role: user.role,
            status: user.status || 'active',
            registeredOn: user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A',
            kycStatus: user.kycStatus || 'N/A',
            averageRating: user.averageRating ? user.averageRating.toFixed(1) : 'N/A',
            jobsCompleted: user.jobsCompleted || 0,
            assignedCities: user.assignedCities && user.assignedCities.length > 0 ? user.assignedCities.join(', ') : 'N/A',
            skills: user.skills && user.skills.length > 0 ? user.skills.join(', ') : 'N/A'
        }));

        const filePath = path.join(__dirname, 'users_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'fullName', title: 'Full Name' },
                { id: 'email', title: 'Email' },
                { id: 'phoneNumber', title: 'Phone Number' },
                { id: 'role', title: 'Role' },
                { id: 'status', title: 'Status' },
                { id: 'registeredOn', title: 'Registered On' },
                { id: 'kycStatus', title: 'KYC Status' },
                { id: 'averageRating', title: 'Average Rating' },
                { id: 'jobsCompleted', title: 'Jobs Completed' },
                { id: 'assignedCities', title: 'Assigned Cities' },
                { id: 'skills', title: 'Assigned Services/Skills' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Users_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT USERS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export users report.' });
    }
});

app.get('/api/reports/providers', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const providers = await User.find({ role: 'technician' }).select('-password');
        const records = providers.map(p => ({
            name: p.fullName,
            email: p.email,
            phone: p.phoneNumber || 'N/A',
            kycStatus: p.kycStatus || 'N/A',
            skills: p.skills ? p.skills.join(', ') : 'N/A',
            rating: p.averageRating ? p.averageRating.toFixed(1) : 'N/A',
            totalJobs: p.jobsCompleted || 0,
            status: p.status || 'Active',
            bankName: p.bankDetails ? p.bankDetails.bankName || '' : '',
            accountNumber: p.bankDetails ? p.bankDetails.accountNumber || '' : '',
            ifscCode: p.bankDetails ? p.bankDetails.ifscCode || '' : '',
            upiId: p.bankDetails ? p.bankDetails.upiId || '' : ''
        }));

        const filePath = path.join(__dirname, 'providers_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'name', title: 'Name' },
                { id: 'email', title: 'Email' },
                { id: 'phone', title: 'Phone' },
                { id: 'kycStatus', title: 'KYC Status' },
                { id: 'skills', title: 'Assigned Skills' },
                { id: 'rating', title: 'Rating' },
                { id: 'totalJobs', title: 'Total Jobs' },
                { id: 'status', title: 'Status' },
                { id: 'bankName', title: 'Bank Name' },
                { id: 'accountNumber', title: 'Account Number' },
                { id: 'ifscCode', title: 'IFSC Code' },
                { id: 'upiId', title: 'UPI ID' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Providers_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT PROVIDERS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export providers report.' });
    }
});

app.get('/api/reports/bookings', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const jobs = await Job.find({})
            .populate('userId', 'fullName email phoneNumber')
            .populate('assignedTechnicianId', 'fullName email phoneNumber');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            customerName: job.userId ? job.userId.fullName : 'N/A',
            customerEmail: job.userId ? job.userId.email : 'N/A',
            customerPhone: job.userId ? job.userId.phoneNumber : 'N/A',
            serviceType: job.applianceType,
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'N/A',
            technicianEmail: job.assignedTechnicianId ? job.assignedTechnicianId.email : 'N/A',
            technicianPhone: job.assignedTechnicianId ? job.assignedTechnicianId.phoneNumber : 'N/A',
            city: job.location ? job.location.city : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleString() : 'N/A',
            status: job.status,
            paymentStatus: job.payment && job.payment.status ? job.payment.status : 'Pending',
            totalAmount: job.quotation ? job.quotation.totalEstimate.toFixed(2) : '0.00',
            problemDescription: job.problemDescription || ''
        }));

        const filePath = path.join(__dirname, 'bookings_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'customerName', title: 'Customer Name' },
                { id: 'customerEmail', title: 'Customer Email' },
                { id: 'customerPhone', title: 'Customer Phone' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianEmail', title: 'Technician Email' },
                { id: 'technicianPhone', title: 'Technician Phone' },
                { id: 'city', title: 'City' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'status', title: 'Status' },
                { id: 'paymentStatus', title: 'Payment Status' },
                { id: 'totalAmount', title: 'Total Amount (₹)' },
                { id: 'problemDescription', title: 'Problem Description' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Bookings_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT BOOKINGS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export bookings report.' });
    }
});
app.get('/api/reports/earnings', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const paidJobs = await Job.find({ 'payment.status': 'Paid' }).populate('userId', 'fullName').populate('assignedTechnicianId', 'fullName');
        
        const records = paidJobs.map(job => {
            const grossAmount = job.quotation ? job.quotation.totalEstimate : 0;
            const appCommission = grossAmount * APP_COMMISSION_RATE;
            const amountBeforeTax = grossAmount - appCommission;
            const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
            const netEarning = amountBeforeTax - technicianTaxDeduction;

            return {
                jobId: job.jobId,
                customerName: job.userId ? job.userId.fullName : 'N/A',
                technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'N/A',
                serviceType: job.applianceType,
                grossAmountPaid: grossAmount.toFixed(2),
                appCommission: appCommission.toFixed(2),
                technicianTaxDeduction: technicianTaxDeduction.toFixed(2),
                netEarningTechnician: netEarning.toFixed(2),
                paidDate: job.payment.paidAt ? new Date(job.payment.paidAt).toLocaleDateString() : 'N/A'
            };
        });

        const filePath = path.join(__dirname, 'earnings_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'customerName', title: 'Customer Name' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'grossAmountPaid', title: 'Gross Amount Paid (₹)' },
                { id: 'appCommission', title: 'App Commission (₹)' },
                { id: 'technicianTaxDeduction', title: 'Tax Deduction (₹)' },
                { id: 'netEarningTechnician', title: 'Net Earning (Technician) (₹)' },
                { id: 'paidDate', title: 'Paid Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Earnings_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT EARNINGS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export earnings report.' });
    }
});


app.get('/api/reports/tickets', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const tickets = await Ticket.find({})
            .populate('raisedBy', 'fullName email role')
            .populate('assignedTo', 'fullName email role');

        const records = tickets.map(ticket => ({
            ticketId: ticket.ticketId,
            subject: ticket.subject,
            description: ticket.description || '',
            raisedBy: ticket.raisedBy ? ticket.raisedBy.fullName : 'N/A',
            raisedByEmail: ticket.raisedBy ? ticket.raisedBy.email : 'N/A',
            raisedByRole: ticket.raisedBy ? ticket.raisedBy.role : 'N/A',
            priority: ticket.priority,
            status: ticket.status,
            assignedTo: ticket.assignedTo ? ticket.assignedTo.fullName : 'Unassigned',
            assignedToEmail: ticket.assignedTo ? ticket.assignedTo.email : 'N/A',
            assignedToRole: ticket.assignedTo ? ticket.assignedTo.role : 'N/A',
            lastUpdate: new Date(ticket.lastUpdate).toLocaleString()
        }));

        const filePath = path.join(__dirname, 'tickets_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'ticketId', title: 'Ticket ID' },
                { id: 'subject', title: 'Subject' },
                { id: 'description', title: 'Description' },
                { id: 'raisedBy', title: 'Raised By' },
                { id: 'raisedByEmail', title: 'Raised By Email' },
                { id: 'raisedByRole', title: 'Raised By Role' },
                { id: 'priority', title: 'Priority' },
                { id: 'status', title: 'Status' },
                { id: 'assignedTo', title: 'Assigned To' },
                { id: 'assignedToEmail', title: 'Assigned To Email' },
                { id: 'assignedToRole', title: 'Assigned To Role' },
                { id: 'lastUpdate', title: 'Last Update' }
            ]
        });

        await csvWriter.writeRecords(records); // Returns a promise
        res.download(filePath, 'city_earnings_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { // Try to delete even if send fails
                    if (unlinkErr) console.error('Error deleting CSV file after send error:', unlinkErr);
                });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { // Delete file after send
                    if (unlinkErr) console.error('Error deleting CSV file after successful send:', unlinkErr);
                });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT EARNINGS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export earnings report.' });
    }
});

// Citymanager: Export Service Performance Report (CSV)
app.get('/api/citymanager/reports/service-performance', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const jobs = await Job.find({
            'location.city': { $in: cityManager.assignedCities },
            status: { $in: ['Completed', 'Cancelled'] } // Consider completed and cancelled jobs for performance
        }).populate('assignedTechnicianId', 'fullName email averageRating');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            serviceType: job.applianceType,
            status: job.status,
            city: job.location ? job.location.city : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Unassigned',
            technicianRating: job.assignedTechnicianId ? job.assignedTechnicianId.averageRating : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleDateString() : 'N/A',
            completedDate: job.updatedAt ? new Date(job.updatedAt).toLocaleDateString() : 'N/A' // Assuming update time for completion/cancellation
        }));

        const filePath = path.join(__dirname, 'city_service_performance_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'status', title: 'Status' },
                { id: 'city', title: 'City' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianRating', title: 'Technician Rating' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'completedDate', title: 'Completed/Cancelled Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'city_service_performance_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                 fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT SERVICE PERFORMANCE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export service performance report.' });
    }
});

// Citymanager: Export Complaints Report (CSV)
app.get('/api/citymanager/reports/complaints', authenticateToken, authorizeRoles(['Citymanager']), async (req, res) => {
    try {
        const cityManager = req.user;
        if (!cityManager.assignedCities || cityManager.assignedCities.length === 0) {
            return res.status(400).json({ success: false, message: 'No cities assigned to this Citymanager.' });
        }

        const userIdsInCities = await User.find({ city: { $in: cityManager.assignedCities } }).select('_id');
        const tickets = await Ticket.find({ raisedBy: { $in: userIdsInCities.map(u => u._id) } })
                                    .populate('raisedBy', 'fullName email')
                                    .populate('assignedTo', 'fullName email');

        const records = tickets.map(ticket => ({
            ticketId: ticket.ticketId,
            raisedBy: ticket.raisedBy ? ticket.raisedBy.fullName : 'N/A',
            raisedByEmail: ticket.raisedBy ? ticket.raisedBy.email : 'N/A',
            subject: ticket.subject,
            description: ticket.description,
            status: ticket.status,
            priority: ticket.priority,
            assignedTo: ticket.assignedTo ? ticket.assignedTo.fullName : 'Unassigned',
            lastUpdate: new Date(ticket.lastUpdate).toLocaleString()
        }));

        const filePath = path.join(__dirname, 'city_complaints_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'ticketId', title: 'Ticket ID' },
                { id: 'raisedBy', title: 'Raised By' },
                { id: 'raisedByEmail', title: 'Raised By Email' },
                { id: 'subject', title: 'Subject' },
                { id: 'description', title: 'Description' },
                { id: 'status', title: 'Status' },
                { id: 'priority', title: 'Priority' },
                { id: 'assignedTo', title: 'Assigned To' },
                { id: 'lastUpdate', title: 'Last Update' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'city_complaints_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[Citymanager EXPORT COMPLAINTS ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export complaints report.' });
    }
});


// --- Service Admin Specific API Endpoints ---
app.get('/api/serviceadmin/dashboard-overview', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const serviceAdmin = req.user;
        if (!serviceAdmin.skills || serviceAdmin.skills.length === 0) {
            return res.status(400).json({ success: false, message: 'No services assigned to this Service Admin.' });
        }

        const techniciansInServices = await User.find({
            role: 'technician',
            skills: { $in: serviceAdmin.skills }
        });
        const totalProviders = techniciansInServices.length;
        const activeProviders = techniciansInServices.filter(tech => tech.status === 'active').length;
        const pendingKycApprovals = techniciansInServices.filter(tech => tech.kycStatus === 'pending').length;

        const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const completedJobsThisMonth = await Job.countDocuments({
            applianceType: { $in: serviceAdmin.skills },
            status: 'Completed',
            createdAt: { $gte: startOfMonth }
        });

        const openTickets = await Ticket.countDocuments({
            serviceType: { $in: serviceAdmin.skills },
            status: { $in: ['Open', 'In Progress', 'Escalated'] }
        });

        res.json({
            success: true,
            data: {
                totalProviders,
                activeProviders,
                pendingKycApprovals,
                completedJobsThisMonth,
                openTickets
            }
        });

    } catch (error) {
        console.error('[SERVICE ADMIN DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Service Admin: Suggest Service-Specific Coupon
app.post('/api/serviceadmin/promotions/suggest', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    const { couponCode, discountType, discountValue, minOrderAmount, expiryDate, maxDiscount } = req.body; 
    try {
        const serviceAdmin = req.user;
        const newPromotion = new Promotion({
            couponCode, discountType, discountValue, minOrderAmount, maxDiscount, expiryDate,
            targetAudience: [], // Set dynamically based on targetServices
            status: 'Pending', // Needs Superadmin approval
            suggestedBy: serviceAdmin._id,
            targetServices: serviceAdmin.skills // Record which services suggested this
        });
        await newPromotion.save();
        res.status(201).json({ success: true, message: 'Coupon suggestion submitted for approval!' });
    } catch (error) {
        console.error('[SERVICE ADMIN SUGGEST COUPON ERROR]:', error);
        if (error.code === 11000) return res.status(409).json({ success: false, message: 'Coupon code already exists.' });
        res.status(500).json({ success: false, message: 'Failed to submit coupon suggestion.' });
    }
});

// Service Admin: Suggest Fee Change to Superadmin/Finance
app.post('/api/serviceadmin/fee-recommendations/suggest', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    const { serviceType, feeType, newProposedValue, reason } = req.body;
    try {
        const serviceAdmin = req.user;

        // Ensure the serviceType is one of the admin's assigned skills
        if (!serviceAdmin.skills.includes(serviceType)) {
            return res.status(403).json({ success: false, message: `You are not authorized to suggest fee changes for service type: ${serviceType}.` });
        }

        // Fetch current value for context
        const appliance = await ApplianceType.findOne({ name: serviceType });
        let currentValue = 0;
        if (appliance) {
            if (feeType === 'basePrice') currentValue = appliance.basePrice;
            else if (feeType === 'commissionRate') currentValue = appliance.commissionRate;
            else return res.status(400).json({ success: false, message: 'Invalid fee type specified.' });
        } else {
            return res.status(404).json({ success: false, message: 'Service type not found for current value lookup.' });
        }

        const newRecommendation = new FeeRecommendation({
            serviceType,
            feeType,
            currentValue,
            newProposedValue,
            reason,
            recommendedBy: serviceAdmin._id,
            adminRole: serviceAdmin.role,
            status: 'Pending'
        });
        await newRecommendation.save();
        res.status(201).json({ success: true, message: 'Fee change recommendation submitted for approval!' });
    } catch (error) {
        console.error('[SERVICE ADMIN SUGGEST FEE CHANGE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to submit fee change recommendation.' });
    }
});

// Service Admin: Export Service Performance Report (CSV)
app.get('/api/serviceadmin/reports/service-performance', authenticateToken, authorizeRoles(['Serviceadmin']), async (req, res) => {
    try {
        const serviceAdmin = req.user;
        if (!serviceAdmin.skills || serviceAdmin.skills.length === 0) {
            return res.status(400).json({ success: false, message: 'No services assigned to this Service Admin.' });
        }

        const jobs = await Job.find({
            applianceType: { $in: serviceAdmin.skills },
            status: { $in: ['Completed', 'Cancelled'] } 
        }).populate('assignedTechnicianId', 'fullName email averageRating');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            serviceType: job.applianceType,
            status: job.status,
            city: job.location ? job.location.city : 'N/A',
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'Unassigned',
            technicianRating: job.assignedTechnicianId ? job.assignedTechnicianId.averageRating : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleDateString() : 'N/A',
            completedDate: job.updatedAt ? new Date(job.updatedAt).toLocaleDateString() : 'N/A'
        }));

        const filePath = path.join(__dirname, 'service_admin_performance_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'status', title: 'Status' },
                { id: 'city', title: 'City' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianRating', title: 'Technician Rating' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'completedDate', title: 'Completed/Cancelled Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'service_admin_performance_report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });

    } catch (error) {
        console.error('[SERVICE ADMIN EXPORT SERVICE PERFORMANCE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export service performance report.' });
    }
});


// --- Finance Officer Specific API Endpoints ---
app.get('/api/finance/dashboard-overview', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const endOfToday = new Date();
        endOfToday.setHours(23, 59, 59, 999);

        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay());
        startOfWeek.setHours(0, 0, 0, 0);

        const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

        const dailyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: today, $lte: endOfToday } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const weeklyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: startOfWeek } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const monthlyEarnings = (await Transaction.aggregate([
            { $match: { type: 'PaymentIn', status: 'Success', createdAt: { $gte: startOfMonth } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const pendingPayouts = (await Transaction.aggregate([
            { $match: { type: 'Payout', status: 'Pending' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]))[0]?.total || 0;

        const failedTransactions = await Transaction.countDocuments({ status: 'Failed' });

        res.json({
            success: true,
            data: {
                dailyEarnings: parseFloat(dailyEarnings.toFixed(2)),
                weeklyEarnings: parseFloat(weeklyEarnings.toFixed(2)),
                monthlyEarnings: parseFloat(monthlyEarnings.toFixed(2)),
                pendingPayouts: parseFloat(pendingPayouts.toFixed(2)),
                failedTransactions
            }
        });

    } catch (error) {
        console.error('[FINANCE DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Finance Officer: Get promotions impact (read-only)
app.get('/api/finance/promotions-impact', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    try {
        const promotions = await Promotion.find({}); // Get all promotions
        // In a real system, you'd calculate total discounted amount from Job.payment if coupon was used
        // For now, usageCount is assumed to be tracked.
        res.json({ success: true, promotions });
    } catch (error) {
        console.error('[FINANCE GET PROMOTIONS IMPACT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch promotions impact data.' });
    }
});


// Finance Officer: Get revenue reports by filters
app.get('/api/finance/reports/revenue', authenticateToken, authorizeRoles(['Financeofficer']), async (req, res) => {
    const { period, city, service, format } = req.query; // 'daily', 'weekly', 'monthly', 'yearly', 'csv'
    try {
        let matchStage = { 'payment.status': 'Paid' };

        // Apply date filtering
        const today = new Date();
        if (period === 'daily') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), today.getMonth(), today.getDate()), $lte: new Date(today.getFullYear(), today.getMonth(), today.getDate(), 23, 59, 59, 999) };
        } else if (period === 'weekly') {
            const startOfWeek = new Date(today.getFullYear(), today.getMonth(), today.getDate() - today.getDay());
            matchStage['payment.paidAt'] = { $gte: startOfWeek, $lte: new Date(startOfWeek.getFullYear(), startOfWeek.getMonth(), startOfWeek.getDate() + 6, 23, 59, 59, 999) };
        } else if (period === 'monthly') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), today.getMonth(), 1), $lte: new Date(today.getFullYear(), today.getMonth() + 1, 0, 23, 59, 59, 999) };
        } else if (period === 'yearly') {
            matchStage['payment.paidAt'] = { $gte: new Date(today.getFullYear(), 0, 1), $lte: new Date(today.getFullYear(), 11, 31, 23, 59, 59, 999) };
        }

        // Apply city and service filters
        if (city) {
            matchStage['location.city'] = city;
        }
        if (service) {
            matchStage['applianceType'] = service;
        }

        const reportData = await Job.aggregate([
            { $match: matchStage },
            { $project: {
                grossAmount: '$payment.amount',
                appCommission: { $multiply: ['$payment.amount', APP_COMMISSION_RATE] }
            }},
            { $group: {
                _id: null,
                totalGrossRevenue: { $sum: '$grossAmount' },
                totalCommissionsEarned: { $sum: '$appCommission' },
                // Total payouts and refunds would typically come from Transaction collection,
                // but for simplicity, we'll initialize them to 0 here if not explicitly joined/calculated
                totalPayoutsMade: { $sum: 0 }, 
                totalRefunds: { $sum: 0 } 
            }}
        ]);

        let result = {
            grossRevenue: 0,
            commissionsEarned: 0,
            netRevenue: 0,
            payoutsMade: 0,
            refunds: 0
        };

        if (reportData.length > 0) {
            result.grossRevenue = reportData[0].totalGrossRevenue;
            result.commissionsEarned = reportData[0].totalCommissionsEarned;
            result.netRevenue = result.grossRevenue - result.payoutsMade - result.refunds; // Simplified calculation
        }

        if (format === 'csv') {
            const csvRecords = [{
                'Period': period || 'Overall',
                'City': city || 'All',
                'Service': service || 'All',
                'Gross Revenue (₹)': result.grossRevenue.toFixed(2),
                'Commissions Earned (₹)': result.commissionsEarned.toFixed(2),
                'Net Revenue (₹)': result.netRevenue.toFixed(2),
                'Payouts Made (₹)': result.payoutsMade.toFixed(2),
                'Refunds (₹)': result.refunds.toFixed(2)
            }];

            const filePath = path.join(__dirname, 'finance_revenue_report.csv');
            const csvWriter = createObjectCsvWriter({
                path: filePath,
                header: [
                    { id: 'Period', title: 'Period' },
                    { id: 'City', title: 'City' },
                    { id: 'Service', title: 'Service' },
                    { id: 'Gross Revenue (₹)', title: 'Gross Revenue (₹)' },
                    { id: 'Commissions Earned (₹)', title: 'Commissions Earned (₹)' },
                    { id: 'Net Revenue (₹)', title: 'Net Revenue (₹)' },
                    { id: 'Payouts Made (₹)', title: 'Payouts Made (₹)' },
                    { id: 'Refunds (₹)', title: 'Refunds (₹)' }
                ]
            });

            await csvWriter.writeRecords(csvRecords);
            res.download(filePath, `revenue_report_${period || 'overall'}_${city || 'all'}_${service || 'all'}.csv`, (err) => {
                if (err) {
                    console.error('Error downloading CSV:', err);
                    fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                    res.status(500).json({ success: false, message: 'Error downloading file.' });
                } else {
                    fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                }
            });

        } else {
            // Return JSON for display in panel
            res.json({ success: true, reportData: [{
                periodLabel: period, // For simple display
                grossRevenue: result.grossRevenue,
                netRevenue: result.netRevenue,
                commissionsEarned: result.commissionsEarned,
                payoutsMade: result.payoutsMade,
                refunds: result.refunds
            }] });
        }

    } catch (error) {
        console.error('[FINANCE REVENUE REPORT ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to generate revenue report.' });
    }
});


// --- Support Agent Specific API Endpoints ---
app.get('/api/support/dashboard-overview', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    try {
        const openTickets = await Ticket.countDocuments({ status: 'Open' });
        const inProgressTickets = await Ticket.countDocuments({ status: 'In Progress' });
        const resolvedToday = await Ticket.countDocuments({
            status: 'Resolved',
            lastUpdate: { $gte: new Date().setHours(0, 0, 0, 0), $lte: new Date().setHours(23, 59, 59, 999) }
        });
        const totalTickets = await Ticket.countDocuments({});

        res.json({
            success: true,
            data: {
                openTickets,
                inProgressTickets,
                resolvedToday,
                totalTickets
            }
        });
    } catch (error) {
        console.error('[SUPPORT DASHBOARD OVERVIEW ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data.' });
    }
});

// Support Agent: Profile lookup by email
app.get('/api/support/lookup-profile', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required for lookup.' });
    }
    try {
        const user = await User.findOne({ email }).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User or provider not found.' });
        }
        res.json({ success: true, user });
    } catch (error) {
        console.error('[LOOKUP PROFILE ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to lookup profile.' });
    }
});

// Support Agent: Escalate Ticket
app.post('/api/support/tickets/:ticketId/escalate', authenticateToken, authorizeRoles(['Supportagent']), async (req, res) => {
    const { ticketId } = req.params;
    const { reason } = req.body;
    try {
        const ticket = await Ticket.findOne({ ticketId });
        if (!ticket) {
            return res.status(404).json({ success: false, message: 'Ticket not found.' });
        }
        ticket.status = 'Escalated';
        ticket.escalationReason = reason;
        ticket.lastUpdate = new Date();
        // Optionally, assign to Superadmin or a specific "escalation" role
        // For simplicity, we just mark as escalated. Superadmin will see it.
        await ticket.save();
        res.json({ success: true, message: `Ticket ${ticketId} escalated successfully!` });
    } catch (error) {
        console.error('[ESCALATE TICKET ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to escalate ticket.' });
    }
});


// --- General Reports Export Endpoints (Superadmin) ---

app.get('/api/reports/users', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        const records = users.map(user => ({
            fullName: user.fullName,
            email: user.email,
            phoneNumber: user.phoneNumber || 'N/A',
            role: user.role,
            status: user.status || 'active',
            registeredOn: user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A',
            kycStatus: user.kycStatus || 'N/A',
            averageRating: user.averageRating ? user.averageRating.toFixed(1) : 'N/A',
            jobsCompleted: user.jobsCompleted || 0,
            assignedCities: user.assignedCities && user.assignedCities.length > 0 ? user.assignedCities.join(', ') : 'N/A',
            skills: user.skills && user.skills.length > 0 ? user.skills.join(', ') : 'N/A'
        }));

        const filePath = path.join(__dirname, 'users_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'fullName', title: 'Full Name' },
                { id: 'email', title: 'Email' },
                { id: 'phoneNumber', title: 'Phone Number' },
                { id: 'role', title: 'Role' },
                { id: 'status', title: 'Status' },
                { id: 'registeredOn', title: 'Registered On' },
                { id: 'kycStatus', title: 'KYC Status' },
                { id: 'averageRating', title: 'Average Rating' },
                { id: 'jobsCompleted', title: 'Jobs Completed' },
                { id: 'assignedCities', title: 'Assigned Cities' },
                { id: 'skills', title: 'Assigned Services/Skills' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Users_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT USERS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export users report.' });
    }
});

app.get('/api/reports/providers', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const providers = await User.find({ role: 'technician' }).select('-password');
        const records = providers.map(p => ({
            name: p.fullName,
            email: p.email,
            phone: p.phoneNumber || 'N/A',
            kycStatus: p.kycStatus || 'N/A',
            skills: p.skills ? p.skills.join(', ') : 'N/A',
            rating: p.averageRating ? p.averageRating.toFixed(1) : 'N/A',
            totalJobs: p.jobsCompleted || 0,
            status: p.status || 'Active',
            bankName: p.bankDetails ? p.bankDetails.bankName || '' : '',
            accountNumber: p.bankDetails ? p.bankDetails.accountNumber || '' : '',
            ifscCode: p.bankDetails ? p.bankDetails.ifscCode || '' : '',
            upiId: p.bankDetails ? p.bankDetails.upiId || '' : ''
        }));

        const filePath = path.join(__dirname, 'providers_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'name', title: 'Name' },
                { id: 'email', title: 'Email' },
                { id: 'phone', title: 'Phone' },
                { id: 'kycStatus', title: 'KYC Status' },
                { id: 'skills', title: 'Assigned Skills' },
                { id: 'rating', title: 'Rating' },
                { id: 'totalJobs', title: 'Total Jobs' },
                { id: 'status', title: 'Status' },
                { id: 'bankName', title: 'Bank Name' },
                { id: 'accountNumber', title: 'Account Number' },
                { id: 'ifscCode', title: 'IFSC Code' },
                { id: 'upiId', title: 'UPI ID' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Providers_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT PROVIDERS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export providers report.' });
    }
});

app.get('/api/reports/bookings', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const jobs = await Job.find({})
            .populate('userId', 'fullName email phoneNumber')
            .populate('assignedTechnicianId', 'fullName email phoneNumber');

        const records = jobs.map(job => ({
            jobId: job.jobId,
            customerName: job.userId ? job.userId.fullName : 'N/A',
            customerEmail: job.userId ? job.userId.email : 'N/A',
            customerPhone: job.userId ? job.userId.phoneNumber : 'N/A',
            serviceType: job.applianceType,
            technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'N/A',
            technicianEmail: job.assignedTechnicianId ? job.assignedTechnicianId.email : 'N/A',
            technicianPhone: job.assignedTechnicianId ? job.assignedTechnicianId.phoneNumber : 'N/A',
            city: job.location ? job.location.city : 'N/A',
            scheduledDate: job.scheduledDateTime ? new Date(job.scheduledDateTime).toLocaleString() : 'N/A',
            status: job.status,
            paymentStatus: job.payment && job.payment.status ? job.payment.status : 'Pending',
            totalAmount: job.quotation ? job.quotation.totalEstimate.toFixed(2) : '0.00',
            problemDescription: job.problemDescription || ''
        }));

        const filePath = path.join(__dirname, 'bookings_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'customerName', title: 'Customer Name' },
                { id: 'customerEmail', title: 'Customer Email' },
                { id: 'customerPhone', title: 'Customer Phone' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'technicianEmail', title: 'Technician Email' },
                { id: 'technicianPhone', title: 'Technician Phone' },
                { id: 'city', title: 'City' },
                { id: 'scheduledDate', title: 'Scheduled Date' },
                { id: 'status', title: 'Status' },
                { id: 'paymentStatus', title: 'Payment Status' },
                { id: 'totalAmount', title: 'Total Amount (₹)' },
                { id: 'problemDescription', title: 'Problem Description' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Bookings_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT BOOKINGS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export bookings report.' });
    }
});
app.get('/api/reports/earnings', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const paidJobs = await Job.find({ 'payment.status': 'Paid' }).populate('userId', 'fullName').populate('assignedTechnicianId', 'fullName');
        
        const records = paidJobs.map(job => {
            const grossAmount = job.quotation ? job.quotation.totalEstimate : 0;
            const appCommission = grossAmount * APP_COMMISSION_RATE;
            const amountBeforeTax = grossAmount - appCommission;
            const technicianTaxDeduction = amountBeforeTax * TAX_RATE_INDIA;
            const netEarning = amountBeforeTax - technicianTaxDeduction;

            return {
                jobId: job.jobId,
                customerName: job.userId ? job.userId.fullName : 'N/A',
                technicianName: job.assignedTechnicianId ? job.assignedTechnicianId.fullName : 'N/A',
                serviceType: job.applianceType,
                grossAmountPaid: grossAmount.toFixed(2),
                appCommission: appCommission.toFixed(2),
                technicianTaxDeduction: technicianTaxDeduction.toFixed(2),
                netEarningTechnician: netEarning.toFixed(2),
                paidDate: job.payment.paidAt ? new Date(job.payment.paidAt).toLocaleDateString() : 'N/A'
            };
        });

        const filePath = path.join(__dirname, 'earnings_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'jobId', title: 'Job ID' },
                { id: 'customerName', title: 'Customer Name' },
                { id: 'technicianName', title: 'Technician Name' },
                { id: 'serviceType', title: 'Service Type' },
                { id: 'grossAmountPaid', title: 'Gross Amount Paid (₹)' },
                { id: 'appCommission', title: 'App Commission (₹)' },
                { id: 'technicianTaxDeduction', title: 'Tax Deduction (₹)' },
                { id: 'netEarningTechnician', title: 'Net Earning (Technician) (₹)' },
                { id: 'paidDate', title: 'Paid Date' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Earnings_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT EARNINGS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export earnings report.' });
    }
});


app.get('/api/reports/tickets', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const tickets = await Ticket.find({})
            .populate('raisedBy', 'fullName email role')
            .populate('assignedTo', 'fullName email role');

        const records = tickets.map(ticket => ({
            ticketId: ticket.ticketId,
            subject: ticket.subject,
            description: ticket.description || '',
            raisedBy: ticket.raisedBy ? ticket.raisedBy.fullName : 'N/A',
            raisedByEmail: ticket.raisedBy ? ticket.raisedBy.email : 'N/A',
            raisedByRole: ticket.raisedBy ? ticket.raisedBy.role : 'N/A',
            priority: ticket.priority,
            status: ticket.status,
            assignedTo: ticket.assignedTo ? ticket.assignedTo.fullName : 'Unassigned',
            assignedToEmail: ticket.assignedTo ? ticket.assignedTo.email : 'N/A',
            assignedToRole: ticket.assignedTo ? ticket.assignedTo.role : 'N/A',
            lastUpdate: new Date(ticket.lastUpdate).toLocaleString()
        }));

        const filePath = path.join(__dirname, 'tickets_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'ticketId', title: 'Ticket ID' },
                { id: 'subject', title: 'Subject' },
                { id: 'description', title: 'Description' },
                { id: 'raisedBy', title: 'Raised By' },
                { id: 'raisedByEmail', title: 'Raised By Email' },
                { id: 'raisedByRole', title: 'Raised By Role' },
                { id: 'priority', title: 'Priority' },
                { id: 'status', title: 'Status' },
                { id: 'assignedTo', title: 'Assigned To' },
                { id: 'assignedToEmail', title: 'Assigned To Email' },
                { id: 'assignedToRole', title: 'Assigned To Role' },
                { id: 'lastUpdate', title: 'Last Update' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Tickets_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT TICKETS CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export tickets report.' });
    }
});

app.get('/api/reports/contact-messages', authenticateToken, authorizeRoles(['Superadmin']), async (req, res) => {
    try {
        const messages = await ContactMessage.find({});
        const records = messages.map(msg => ({
            name: msg.name,
            email: msg.email,
            subject: msg.subject,
            message: msg.message,
            receivedOn: new Date(msg.createdAt).toLocaleString()
        }));

        const filePath = path.join(__dirname, 'contact_messages_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'name', title: 'Name' },
                { id: 'email', title: 'Email' },
                { id: 'subject', title: 'Subject' },
                { id: 'message', title: 'Message' },
                { id: 'receivedOn', title: 'Received On' }
            ]
        });

        await csvWriter.writeRecords(records);
        res.download(filePath, 'TechSeva_Contact_Messages_Report.csv', (err) => {
            if (err) {
                console.error('Error downloading CSV:', err);
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
                res.status(500).json({ success: false, message: 'Error downloading file.' });
            } else {
                fs.unlink(filePath, (unlinkErr) => { if (unlinkErr) console.error('Error deleting CSV:', unlinkErr); });
            }
        });
    } catch (error) {
        console.error('[EXPORT CONTACT MESSAGES CSV ERROR]:', error);
        res.status(500).json({ success: false, message: 'Failed to export contact messages report.' });
    }
});


// --- Catch-all 404 Route - Must be placed at the very end ---
app.use((req, res, next) => {
    // For HTML requests, serve a 404 HTML page from views, or inline if file not found
    if (req.accepts('html')) {
        const filePath = path.join(__dirname, 'views', '404.html');
        return res.status(404).sendFile(filePath, (err) => {
            if (err) {
                console.warn(`[404 Handler] 404.html not found at ${filePath}. Serving inline 404 for ${req.path}.`);
                return res.status(404).send(`
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>404 - Page Not Found</title>
                        <style>
                            body { font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #f4f7f6; color: #333; }
                            h1 { font-size: 3em; color: #dc3545; }
                            p { font-size: 1.2em; }
                            a { color: #007bff; text-decoration: none; }
                            a:hover { text-decoration: underline; }
                        </style>
                    </head>
                    <body>
                        <h1>404 - Page Not Found</h1>
                        <p>Oops! The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
                        <p><a href="/">Go to Homepage</a></p>
                    </body>
                    </html>
                `);
            }
        });
    }
    console.warn(`[404 Handler] API request for ${req.path} - Endpoint Not Found.`);
    res.status(404).json({ success: false, message: 'API endpoint not found.' });
});

// --- Start the server ---
app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log('✅ MongoDB connection status will be logged above this line.');
    console.log('Remember to set MONGODB_URI, EMAIL_USER, EMAIL_PASS, API_KEY, SESSION_SECRET, VITE_GOOGLE_MAPS_API_KEY, and GOOGLE_CLIENT_ID in your Render environment variables or .env file!');
});
