import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import bodyParser from 'body-parser';
import pg from 'pg'
import dotenv from 'dotenv';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import fs from 'fs';
import { format } from '@fast-csv/format';

// Definitions
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


dotenv.config()
const port = 3003;
const app = express();
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const pool = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST, 
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

const pool2 = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST, 
    database: process.env.DB_NAME2,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.options('*', cors());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Validates the time value for user signup
 * @param {string} timeValue - The time value to validate
 * @returns {Object} - { valid: boolean, value?: string, error?: string }
 */
function validateTime(timeValue) {
    const predefinedValues = ['Lifetime', '3 days', '1 week', '1 month'];
    
    // Check if predefined value
    if (predefinedValues.includes(timeValue)) {
        return { valid: true, value: timeValue };
    }
    
    // Check if custom datetime (14 digits: YYYYMMDDHHmmss)
    if (/^\d{14}$/.test(timeValue)) {
        try {
            // Parse datetime components
            const year = parseInt(timeValue.substring(0, 4), 10);
            const month = parseInt(timeValue.substring(4, 6), 10);
            const day = parseInt(timeValue.substring(6, 8), 10);
            const hours = parseInt(timeValue.substring(8, 10), 10);
            const minutes = parseInt(timeValue.substring(10, 12), 10);
            const seconds = parseInt(timeValue.substring(12, 14), 10);
            
            // Validate date components
            if (month < 1 || month > 12) {
                return { valid: false, error: 'Invalid month in datetime (must be 01-12)' };
            }
            
            if (hours < 0 || hours > 23) {
                return { valid: false, error: 'Invalid hours in datetime (must be 00-23)' };
            }
            
            if (minutes < 0 || minutes > 59) {
                return { valid: false, error: 'Invalid minutes in datetime (must be 00-59)' };
            }
            
            if (seconds < 0 || seconds > 59) {
                return { valid: false, error: 'Invalid seconds in datetime (must be 00-59)' };
            }
            
            // Create date object (month is 0-indexed in Date constructor)
            const dateString = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}Z`;
            const expiryDate = new Date(dateString);
            
            // Check if date is valid
            if (isNaN(expiryDate.getTime())) {
                return { valid: false, error: 'Invalid datetime format (invalid date)' };
            }
            
            // Check if date is in the future (at least 1 minute from now to be lenient)
            const now = new Date();
            const oneMinuteFromNow = new Date(now.getTime() + 60 * 1000);
            
            if (expiryDate <= oneMinuteFromNow) {
                return { valid: false, error: 'Datetime must be in the future' };
            }
            
            return { valid: true, value: timeValue };
        } catch (error) {
            return { valid: false, error: 'Invalid datetime format' };
        }
    }
    
    // If not predefined and not 14 digits, it's invalid
    return { valid: false, error: 'Invalid time format. Use predefined values (Lifetime, 3 days, 1 week, 1 month) or custom datetime (YYYYMMDDHHmmss)' };
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ 
            res: 'unauthorized', 
            error: 'Invalid or missing authentication token' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ 
                res: 'unauthorized', 
                error: 'Invalid or missing authentication token' 
            });
        }
        req.user = user;
        next();
    });
};

// Authorization middleware for Admin and Platform Developer only
const authorizeAdminOrPlatformDev = async (req, res, next) => {
    try {
        const result = await pool.query(
            'SELECT role FROM users WHERE id = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [req.user.id]
        );

        if (result.rowCount === 0) {
            return res.status(403).json({ 
                res: 'forbidden', 
                error: 'User not found' 
            });
        }

        const userRole = result.rows[0].role;
        
        if (userRole !== 'Admin' && userRole !== 'Platform Developer') {
            return res.status(403).json({ 
                res: 'forbidden', 
                error: 'Access denied. Only Admin and Platform Developer roles can access this endpoint.' 
            });
        }

        next();
    } catch (error) {
        console.error('Authorization error:', error);
        res.status(500).json({ 
            res: 'error', 
            error: 'Internal server error occurred during authorization' 
        });
    }
};

app.get('/',(req,res)=>{
    res.json({res:"API IS GOOD"})
})

app.get('/sayhello',(req,res)=>{
    res.json({res:"API IS Saying Hello"})
})

// Get Users
app.get('/getusers', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users');
        res.json(result.rows);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

// Get All Users (for Manager Tab - Admin and Platform Developer only)
app.get('/getallusers', authenticateToken, authorizeAdminOrPlatformDev, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                username,
                name,
                email,
                role,
                location,
                mobilenumber,
                defaultstartwindow,
                shownodeslocationbydefault,
                expandSidePanelOnEditMode,
                roles,
                usertime
            FROM users
            WHERE (isdeleted = false OR isdeleted IS NULL)
            ORDER BY username ASC
        `);

        // Format the response
        const users = result.rows.map(user => ({
            username: user.username || '',
            name: user.name || '',
            email: user.email || '',
            role: user.role || '',
            location: user.location || '',
            mobilenumber: user.mobilenumber || '',
            defaultstartwindow: user.defaultstartwindow || '',
            shownodeslocationbydefault: user.shownodeslocationbydefault || false,
            expandSidePanelOnEditMode: user.expandsidepaneloneditmode || false,
            roles: user.roles || {},
            usertime: user.usertime || 'Lifetime'
        }));

        res.json({ 
            res: 'users fetched', 
            users: users 
        });
    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ 
            res: 'error', 
            error: 'Internal server error occurred while fetching users' 
        });
    }
});

// Modify validateuser endpoint to include roles in response
app.post('/validateuser', async (req, res) => {
    const {username, password, rememberme} = req.body;
    // Exclude deleted users from login
    const result = await pool.query('SELECT * FROM users WHERE username=$1 AND (isdeleted = false OR isdeleted IS NULL)', [username]);
    if(!result.rowCount==0){
        const user = result.rows[0];
        const passwordHashFrompool = user.password_hash;
        const isMatch = await bcrypt.compare(password, passwordHashFrompool);
        if(isMatch){
            const ret = await pool.query('UPDATE users SET isloggedin=true, isrememberme=$1 WHERE id=$2 RETURNING *', [rememberme, user.id]);
            let duration = rememberme ? '1h' : '10m';
            
            const token = jwt.sign(
                { id: user.id, email: user.username },
                process.env.JWT_SECRET,
                { expiresIn: duration }
            );
            
            if(ret.rows){
                // Include roles in response
                res.json({
                    'res': 'authorized',
                    'user': {
                        ...user,
                        roles: user.roles // Include roles from database
                    },
                    'rememberme': rememberme,
                    'token': token
                });
            }
        } else {
            res.json({'res': 'wrong password'});
        }
    } else {
        res.json({'res': "user not found"});
    }
});

// Add User (Protected - Admin and Platform Developer only)
app.post('/adduser', async (req, res) => {
    try {
        // 1. Extract and validate JWT token from Authorization header
        const authHeader = req.headers['authorization'];
        
        console.log('Auth header:', authHeader ? 'Present' : 'Missing');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('No Bearer token - allowing public signup');
            // Allow public signup as well
            const { username, password, email, mobile, name, role, location, roles, time } = req.body;
            
            if (!username || !password || !email || !mobile) {
                return res.status(400).json({ res: 'error', message: 'All fields are required' });
            }

            // Validate time parameter
            const timeValue = time || '3 days';
            const timeValidation = validateTime(timeValue);
            if (!timeValidation.valid) {
                return res.status(400).json({ res: 'error', message: `Invalid time format: ${timeValidation.error}` });
            }

            // Check if email exists (exclude deleted users)
            const existingEmail = await pool.query('SELECT email FROM users WHERE email = $1 AND (isdeleted = false OR isdeleted IS NULL)', [email]);
            if (existingEmail.rowCount > 0) {
                return res.json({ res: 'email exists' });
            }

            // Check if username exists (exclude deleted users)
            const existingUser = await pool.query('SELECT username FROM users WHERE username = $1 AND (isdeleted = false OR isdeleted IS NULL)', [username]);
            if (existingUser.rowCount > 0) {
                return res.json({ res: 'username exists' });
            }

            // Hash password and create user
            const saltRounds = 10;
            const passwordHash = await bcrypt.hash(password, saltRounds);
            
            const result = await pool.query(
                `INSERT INTO users (username, password_hash, email, role, created_at, mobilenumber, name, location, roles, usertime) 
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', $5, $6, $7, $8::jsonb, $9) 
                 RETURNING id, username, email, role, created_at`,
                [username, passwordHash, email, role || 'Viewer', mobile, name, location, JSON.stringify(roles || {}), time || '3 days']
            );
            
            console.log(`User created (public): ${username}`);
            return res.status(201).json({ res: 'user created', user: result.rows[0] });
        }

        const token = authHeader.split(' ')[1];

        // 2. Verify JWT token
        let decodedUser;
        try {
            decodedUser = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Token decoded successfully. User ID:', decodedUser.id);
        } catch (tokenError) {
            console.log('Token verification failed:', tokenError.message);
            return res.status(401).json({
                res: 'unauthorized',
                error: 'Invalid or expired authentication token'
            });
        }

        // 3. Verify user exists and get their current role from database
        const requestingUserResult = await pool.query(
            'SELECT id, username, role FROM users WHERE id = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [decodedUser.id]
        );

        console.log('Query result:', requestingUserResult.rowCount, 'rows');

        if (requestingUserResult.rowCount === 0) {
            console.log('User not found in database with ID:', decodedUser.id);
            return res.status(401).json({
                res: 'unauthorized',
                error: 'User not found'
            });
        }

        const requestingUser = requestingUserResult.rows[0];
        console.log(`User found: ${requestingUser.username}, Role: ${requestingUser.role}`);

        // 4. Verify requesting user has Admin or Platform Developer role
        if (requestingUser.role !== 'Admin' && requestingUser.role !== 'Platform Developer') {
            console.log(`Unauthorized: ${requestingUser.username} has role ${requestingUser.role}`);
            return res.status(403).json({
                res: 'forbidden',
                error: 'Only Admin and Platform Developer users can create new accounts'
            });
        }

        // 5. Log the signup attempt for audit purposes
        console.log(`User creation initiated by: ${requestingUser.username} (${requestingUser.role})`);

        // 6. Extract signup data
        const { username, password, email, mobile, name, role, location, roles, time } = req.body;
        
        if (!username || !password || !email || !mobile) {
            return res.status(400).json({ res: 'error', message: 'All fields are required' });
        }

        // Validate time parameter
        const timeValue = time || '3 days';
        const timeValidation = validateTime(timeValue);
        if (!timeValidation.valid) {
            return res.status(400).json({ res: 'error', message: `Invalid time format: ${timeValidation.error}` });
        }

        // 7. Check if email exists (exclude deleted users)
        const existingEmail = await pool.query('SELECT email FROM users WHERE email = $1 AND (isdeleted = false OR isdeleted IS NULL)', [email]);
        if (existingEmail.rowCount > 0) {
            return res.json({ res: 'email exists' });
        }

        // 8. Check if username exists (exclude deleted users)
        const existingUser = await pool.query('SELECT username FROM users WHERE username = $1 AND (isdeleted = false OR isdeleted IS NULL)', [username]);
        if (existingUser.rowCount > 0) {
            return res.json({ res: 'username exists' });
        }

        // 9. Hash password and create user
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, email, role, created_at, mobilenumber, name, location, roles, usertime) 
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', $5, $6, $7, $8::jsonb, $9) 
             RETURNING id, username, email, role, created_at`,
            [username, passwordHash, email, role || 'Viewer', mobile, name, location, JSON.stringify(roles || {}), time || '3 days']
        );
        
        // 10. Log successful user creation
        console.log(`User created successfully: ${username} by ${requestingUser.username}`);
        
        res.status(201).json({ res: 'user created', user: result.rows[0] });
    } catch (error) {
        // Check for specific error types
        if (error.code === '23505') { // Unique violation
            // Check if it's an email or username violation
            if (error.detail.includes('email')) {
                return res.json({ res: 'email exists' });
            } else {
                return res.json({ res: 'username exists' });
            }
        } else if (error.code === '23502') { // Not null violation
            return res.status(400).json({ res: 'error', message: 'Missing required fields' });
        } else if (error.code === '22P02') { // Invalid input syntax
            return res.status(400).json({ res: 'error', message: 'Invalid input format' });
        }
        
        // Generic error
        console.error('Error creating user:', error);
        res.status(500).json({ res: 'error', message: 'Server error creating user'});
    }
});

// Get per-user nodes display order
app.get('/getnodesorder', async (req, res) => {
    try {
        const { username } = req.query;

        if (!username) {
            return res.status(400).json({ res: 'error', error: 'username is required' });
        }

        const result = await pool.query(
            'SELECT nodes_display_order FROM users WHERE username = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [username]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ res: 'error', error: 'user not found' });
        }

        let order = result.rows[0].nodes_display_order;

        // nodes_display_order is expected to be json/jsonb, but could be null/empty
        if (!order || (typeof order === 'object' && Object.keys(order).length === 0)) {
            return res.json({ res: 'no order', order: {} });
        }

        // If stored as text, try to parse
        if (typeof order === 'string') {
            try {
                order = JSON.parse(order);
            } catch (e) {
                console.error('Failed to parse nodes_display_order for user', username, e);
                return res.json({ res: 'no order', order: {} });
            }
        }

        return res.json({ res: 'nodesorder fetched', order });
    } catch (error) {
        console.error('Error in /getnodesorder:', error);
        res.status(500).json({ res: 'error', error: 'server error fetching nodes order' });
    }
});

// Save per-user nodes display order
app.post('/savenodesorder', async (req, res) => {
    try {
        const { username, order } = req.body;

        if (!username) {
            return res.status(400).json({ res: 'error', error: 'username is required' });
        }

        if (!order || typeof order !== 'object' || Array.isArray(order)) {
            return res.status(400).json({ res: 'error', error: 'order must be an object {unid: position}' });
        }

        // Basic validation: keys are strings, values are positive integers
        for (const [unid, pos] of Object.entries(order)) {
            if (typeof unid !== 'string') {
                return res.status(400).json({ res: 'error', error: 'order keys must be meter unid strings' });
            }
            const num = Number(pos);
            if (!Number.isInteger(num) || num <= 0) {
                return res.status(400).json({ res: 'error', error: 'order values must be positive integers' });
            }
        }

        // Ensure user exists and update their nodes_display_order (only for non-deleted users)
        const updateResult = await pool.query(
            'UPDATE users SET nodes_display_order = $1::jsonb WHERE username = $2 AND (isdeleted = false OR isdeleted IS NULL) RETURNING id',
            [JSON.stringify(order), username]
        );

        if (updateResult.rowCount === 0) {
            return res.status(404).json({ res: 'error', error: 'user not found' });
        }

        return res.json({ res: 'nodesorder saved' });
    } catch (error) {
        console.error('Error in /savenodesorder:', error);
        res.status(500).json({ res: 'error', error: 'server error saving nodes order' });
    }
});

// Update User Roles (Protected - Admin and Platform Developer only)
app.post('/updateuserroles', authenticateToken, authorizeAdminOrPlatformDev, async (req, res) => {
    try {
        const { roleUpdates } = req.body;

        // 1. Input Validation
        if (!roleUpdates || !Array.isArray(roleUpdates) || roleUpdates.length === 0) {
            return res.status(400).json({
                res: 'error',
                error: 'Invalid request. roleUpdates must be an array with at least one item.'
            });
        }

        // 2. Validate each role update item
        const validRoles = ['Admin', 'Platform Developer', 'Editor', 'Viewer'];
        const notFoundUsers = [];
        const updated = [];

        for (const update of roleUpdates) {
            const { username, role } = update;

            // Validate fields
            if (!username || typeof username !== 'string' || username.trim() === '') {
                return res.status(400).json({
                    res: 'error',
                    error: 'Each role update must have a valid username string.'
                });
            }

            if (!role || !validRoles.includes(role)) {
                return res.status(400).json({
                    res: 'error',
                    error: `Invalid role. Must be one of: ${validRoles.join(', ')}`
                });
            }

            // 3. Check if user exists and get old role for logging (exclude deleted users)
            const userCheck = await pool.query(
                'SELECT id, role FROM users WHERE username = $1 AND (isdeleted = false OR isdeleted IS NULL)',
                [username]
            );

            if (userCheck.rowCount === 0) {
                notFoundUsers.push(username);
                continue;
            }

            const oldRole = userCheck.rows[0].role;

            // 4. Update user role (only for non-deleted users)
            const updateResult = await pool.query(
                'UPDATE users SET role = $1 WHERE username = $2 AND (isdeleted = false OR isdeleted IS NULL) RETURNING username, role',
                [role, username]
            );

            if (updateResult.rowCount > 0) {
                updated.push({
                    username: updateResult.rows[0].username,
                    role: updateResult.rows[0].role
                });

                // 5. Audit logging
                console.log(`Role updated: User '${username}' role changed from '${oldRole}' to '${role}' by user ID ${req.user.id} at ${new Date().toISOString()}`);
            }
        }

        // 6. Handle not found users
        if (notFoundUsers.length > 0) {
            return res.status(404).json({
                res: 'user not found',
                error: 'One or more users not found',
                usernames: notFoundUsers
            });
        }

        // 7. Return success response
        res.json({
            res: 'roles updated',
            updated: updated
        });

    } catch (error) {
        console.error('Error updating user roles:', error);
        res.status(500).json({
            res: 'error',
            error: 'Internal server error occurred while updating user roles'
        });
    }
});

// Delete User (Protected - Admin and Platform Developer only)
app.delete('/deleteuser', authenticateToken, authorizeAdminOrPlatformDev, async (req, res) => {
    try {
        const { username } = req.query;

        // 1. Input Validation
        if (!username || typeof username !== 'string' || username.trim() === '') {
            return res.status(400).json({
                res: 'error',
                error: 'Username parameter is required'
            });
        }

        // 2. Get requesting user's role (exclude deleted users)
        const requestingUserResult = await pool.query(
            'SELECT role FROM users WHERE id = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [req.user.id]
        );

        if (requestingUserResult.rowCount === 0) {
            return res.status(401).json({
                res: 'unauthorized',
                error: 'Requesting user not found'
            });
        }

        const requestingUserRole = requestingUserResult.rows[0].role;

        // 3. Check if target user exists (exclude already deleted users)
        const targetUserResult = await pool.query(
            'SELECT id, username, role FROM users WHERE username = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [username]
        );

        if (targetUserResult.rowCount === 0) {
            return res.status(404).json({
                res: 'user not found',
                error: `User with username '${username}' not found`
            });
        }

        const targetUser = targetUserResult.rows[0];

        // 4. Permission Check: Admin cannot delete Platform Developer
        if (requestingUserRole === 'Admin' && targetUser.role === 'Platform Developer') {
            console.log(`Forbidden deletion attempt: Admin (ID: ${req.user.id}) tried to delete Platform Developer '${username}'`);
            return res.status(403).json({
                res: 'forbidden',
                error: 'You do not have permission to delete this user. Platform Developers cannot be deleted by Admins.'
            });
        }

        // 5. Safety Check: Prevent deletion of last Admin/Platform Developer (exclude already deleted users)
        const roleCountResult = await pool.query(
            'SELECT COUNT(*) as count FROM users WHERE role = $1 AND (isdeleted = false OR isdeleted IS NULL)',
            [targetUser.role]
        );

        const roleCount = parseInt(roleCountResult.rows[0].count);

        if ((targetUser.role === 'Admin' || targetUser.role === 'Platform Developer') && roleCount <= 1) {
            console.log(`Safety check failed: Attempted to delete last ${targetUser.role} '${username}'`);
            return res.status(409).json({
                res: 'error',
                error: `Cannot delete user. This user is the last ${targetUser.role} in the system.`
            });
        }

        // 6. Soft Delete using isdeleted column only
        const deleteResult = await pool.query(
            `UPDATE users 
             SET isdeleted = true,
                 isloggedin = false
             WHERE username = $1 
             AND (isdeleted = false OR isdeleted IS NULL)
             RETURNING id`,
            [username]
        );

        if (deleteResult.rowCount === 0) {
            return res.status(500).json({
                res: 'error',
                error: 'Failed to delete user'
            });
        }

        // 7. Audit logging
        console.log(`User deleted: '${username}' (${targetUser.role}) deleted by user ID ${req.user.id} at ${new Date().toISOString()}`);

        // 8. Return success response
        res.json({
            res: 'user deleted',
            username: username
        });

    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            res: 'error',
            error: 'Internal server error occurred while deleting user'
        });
    }
});

app.get('/getchartdata', async (req, res) => {
    try {
        const { meterid, day } = req.query;

        if (!meterid) {
            return res.status(400).json({ res: 'meterid is required' });
        }

        let startTime;
        let endTime;

        if (day) {
            // Expecting day in format DD-MM-YYYY, e.g. 24-11-2025
            const parts = String(day).split('-');
            if (parts.length !== 3) {
                return res.status(400).json({ res: 'day must be in format DD-MM-YYYY' });
            }

            const [ddStr, mmStr, yyyyStr] = parts;
            const dd = Number(ddStr);
            const mm = Number(mmStr);
            const yyyy = Number(yyyyStr);

            if (!dd || !mm || !yyyy) {
                return res.status(400).json({ res: 'day must be in format DD-MM-YYYY with numeric values' });
            }

            const yyyyPadded = String(yyyy).padStart(4, '0');
            const mmPadded = String(mm).padStart(2, '0');
            const ddPadded = String(dd).padStart(2, '0');

            // Build the exact Cairo day window in UTC so we don't leak into the next Cairo day
            const tz = 'Africa/Cairo';
            // Base UTC midnight for that calendar day
            const baseUtcMidnight = new Date(Date.UTC(Number(yyyyPadded), Number(mmPadded) - 1, Number(ddPadded), 0, 0, 0));
            // Same instant shown in Cairo time
            const cairoViewOfBaseMidnight = new Date(baseUtcMidnight.toLocaleString('en-US', { timeZone: tz }));
            const offsetMs = cairoViewOfBaseMidnight.getTime() - baseUtcMidnight.getTime();

            // Cairo day start (00:00 in Cairo) expressed in UTC
            startTime = new Date(baseUtcMidnight.getTime() - offsetMs);
            // End of that Cairo day (just before next midnight)
            endTime = new Date(startTime.getTime() + 24 * 60 * 60 * 1000 - 1);

            // Shift the whole window one hour back to compensate for observed 1-hour drift
            const oneHourMs = 60 * 60 * 1000;
            startTime = new Date(startTime.getTime() - oneHourMs);
            endTime = new Date(endTime.getTime() - oneHourMs);
        } else {
            // Default: use current day in Africa/Cairo (to be consistent with /downloadlog)
            const nowUtc = new Date();
            const cairoNow = new Date(nowUtc.toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
            const cairoStartOfDay = new Date(cairoNow);
            cairoStartOfDay.setHours(0, 0, 0, 0);

            startTime = cairoStartOfDay;
            endTime = cairoNow;
        }

        // Fetch readings for this meter and time window from the same table used in /downloadlog (mqttmeter)
        const result = await pool.query(
            `SELECT timestamp, msg 
             FROM mqttmeter 
             WHERE meterid = $1 
               AND timestamp >= $2 
               AND timestamp <= $3
             ORDER BY timestamp ASC`,
            [meterid, startTime.toISOString(), endTime.toISOString()]
        );

        // Return all readings for that day, with msg parsed the same way as /downloadlog
        const readings = result.rows.map(row => {
            // Convert timestamp to Africa/Cairo and format as "YYYY-MM-DD HH:MM:SS"
            const tsCairo = new Date(new Date(row.timestamp).toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
            const yyyy = tsCairo.getFullYear();
            const mm = String(tsCairo.getMonth() + 1).padStart(2, '0');
            const dd = String(tsCairo.getDate()).padStart(2, '0');
            const hh = String(tsCairo.getHours()).padStart(2, '0');
            const min = String(tsCairo.getMinutes()).padStart(2, '0');
            const ss = String(tsCairo.getSeconds()).padStart(2, '0');
            const formattedTimestamp = `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;

            let msgObj = {};
            try {
                msgObj = JSON.parse(row.msg);
            } catch (err) {
                console.warn('Invalid JSON in msg for /getchartdata:', row.msg);
            }
            delete msgObj.unid;
            delete msgObj.error_code;

            return {
                timestamp: formattedTimestamp,
                ...msgObj
            };
        });

        res.json({ res: 'chartdata fetched', data: readings });
    } catch (error) {
        console.error('Error in /getchartdata:', error);
        res.status(500).json({ res: 'error fetching chartdata' });
    }
});

// Download log file
app.get('/downloadlog', async (req, res) => {
    const metername = req.query.metername;
    const meterid = req.query.meterid;
    let downloadName = req.query.metername || 'meter-log.csv';
    if (!downloadName.endsWith('.csv')) {
        downloadName += '.csv';
    }

    const filePath = path.join(__dirname, 'public', 'meter-logs', 'meter1-log.csv');
    console.log('Download log for meter ID:', meterid, 'Filename:', downloadName, 'Meter Name:', metername);

    if (!metername) {
    return res.status(400).send('Missing "metername" query parameter.');
    }
    if (!meterid) {
    return res.status(400).send('Missing "meterid" query parameter.');
    }

    try {
    const result = await pool.query(
        'SELECT timestamp, msg FROM mqttmeter WHERE meterid = $1 ORDER BY timestamp DESC',
        [meterid]
    );

    if (result.rows.length === 0) {
        return res.status(404).send('No data found for the given meter ID.');
    }

    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    const writeStream = fs.createWriteStream(filePath);

    // Dynamically get all keys from parsed msg objects
    const allKeys = new Set();
    const processedRows = result.rows.map(row => {
        let msgObj = {};
        try {
        msgObj = JSON.parse(row.msg);
        } catch (err) {
        console.warn('Invalid JSON in msg:', row.msg);
        }
        delete msgObj.unid;
        Object.keys(msgObj).forEach(key => allKeys.add(key));
        return {
        timestamp: new Date(new Date(row.timestamp).toLocaleString('en-US', { timeZone: 'Africa/Cairo' })).toString().replace(' (Central European Summer Time)', ''),
        ...msgObj
        };
    });

    console.log(processedRows)
    const csvHeaders = ['timestamp', ...Array.from(allKeys)];
    const csvStream = format({ headers: csvHeaders });
    csvStream.pipe(writeStream);

    processedRows.forEach(row => {
        const csvRow = {
        timestamp: row.timestamp,
        };
        csvHeaders.slice(1).forEach(key => {
        csvRow[key] = row[key] !== undefined ? row[key] : ''});
        csvStream.write(csvRow);
    });

    csvStream.end();

    writeStream.on('finish', () => {
        res.download(filePath, downloadName, (err) => {
        if (err) {
            console.error('Download error:', err);
            res.status(500).send('Error sending file.');
        }
        });
    });

    writeStream.on('error', (err) => {
        console.error('Write error:', err);
        res.status(500).send('Error writing file.');
    });

    } catch (err) {
    console.error('DB error:', err);
    res.status(500).send('Database error.');
    }
});


app.post('/savetreeandsettings', async (req, res) => {
    console.log(req.body);
    const { editedTree, currentSettings } = req.body;
    const currentSettingsJson = JSON.stringify(currentSettings);
    const result = await pool.query('UPDATE treeandsettings SET tree=$1, settings=$2 where id=1', [editedTree, currentSettingsJson]);
    res.json({ res: 'tree and settings saved' });
});

app.get('/gettreeandsettings', async (req, res) => {
    const result = await pool.query('SELECT * FROM treeandsettings where id=1');
    res.json({ res: 'tree and settings fetched', data: result.rows[0] });
});


// Save tree
app.post('/savetree', async (req, res) => {
    try {
        const tree  = req.body.changedTree;
        // console.log(tree)
        const dbresult = await pool.query(
            "insert into treeandsettings (tree) values ($1) returning id",
            [tree]
        )
        console.log('saved tree to id '+ dbresult.rows[0].id)
        res.json({'res':"received Tree"})
    } catch (error) {
        res.status(500).json({ error: 'Failed to save tree' });
    }
});

// Get tree and settings
app.get('/gettree', async (req, res) => {
    try {
        // Get tree
        const treeResult = await pool.query(
            'SELECT * FROM treeandsettings order by id desc'
        );
        // console.log(treeResult.rows)
        res.json({
            tree: treeResult.rows[0].tree
        });
        // console.log()
        console.log(`tree sent ${treeResult.rows[0].id}`)
    } catch (error) {
        console.log('err',error)
        res.status(500).json({ error: 'Failed to fetch tree and settings' });
    }
});

// Get all meters settings
app.get('/getallmetersettings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM meter_settings');
        res.json({ 
            success: true, 
            settings: result.rows,
            allmeters: result.rows.map(row => row.meter_id.toString())
        });
    } catch (error) {
        console.error('Error getting all meter settings:', error);
        res.status(500).json({ success: false, message: 'Error getting settings', error: error.message });
    }
});

app.post('/addnewsettings', async (req, res) => {
    const changes = req.body;
    console.log(changes);
    changes.forEach(async (change) => {
        const query = change[0];
        const unid = query.match(/where unid='([0-9a-fA-F-]{36})'/);
        try {
            // Check if the unid already exists
            if (unid && unid[1]) {
                const existing = await pool.query('SELECT 1 FROM meter_settings WHERE unid = $1', [unid[1]]);
                if (existing.rowCount > 0) {
                    console.log(`Skipping insert for existing unid: ${unid[1]}`);
                    return; // Skip this iteration
                }
            }
        } catch (error) {
            console.error('Error checking existing unid:', error);
            res.status(500).json({ success: false, message: 'Error checking existing settings', error: error.message });
        }
        const values = change[1];
        try {
            await pool.query(query, values);
        } catch (error) {
            console.error('Error inserting meter settings:', error);
            res.status(500).json({ success: false, message: 'Error inserting settings', error: error.message });
        }
    });
    res.json({ res: 'Settings Added'});
});

app.post('/deletemetersetting', async (req, res) => {
    const unids = req.body;
    console.log('Deleting meter settings for unids:', unids);
    try {
        const result = await pool.query('DELETE FROM meter_settings WHERE unid = ANY($1::text[]) returning *', [unids]);
        const deletedUnids = result.rows.map(row => row.unid);
        console.log('Deleted meter settings:', deletedUnids);
        res.json({ res: 'Settings Deleted', deletedUnids });
    } catch (error) {
        console.error('Error deleting meter settings:', error);
        res.status(500).json({ success: false, message: 'Error deleting meter settings', error: error.message });
    }
});

app.post('/updatemetersetting', async (req, res) => {
    const changes = req.body;
    console.log(changes);
    let dbResults = [];
    let errorsOccurred = [];
    await Promise.all(changes.map(async (change) => {
        const query = change[0];
        const unid = query.match(/where unid='([0-9a-fA-F-]{36})'/);
        if (!unid || !unid[1]) {
            console.error('Invalid or missing unid in query:', query);
            return; // Skip this iteration
        }
        const values = change[1];
        try {
            const dbRes = await pool.query(query, values);
            dbResults.push(dbRes.rows[0]);
        } catch (error) {
            console.error('Error updating meter settings:', error);
            errorsOccurred.push({ error: error.message, unid: unid[1] } );
        }
    }));
    console.log('Update results:', dbResults);
    console.log('Update errors:', errorsOccurred);
    res.json({ res: 'Settings updated', data: dbResults, errors: errorsOccurred });
});

app.get('/updateusershowlocation', async (req, res) => {
    const {username,showNodesLocationByDefault} = req.query
    console.log(username,showNodesLocationByDefault)
    const result = await pool.query('UPDATE users SET showNodesLocationByDefault=$1 WHERE username=$2', [showNodesLocationByDefault, username]);
    res.json({ res: 'User updated'});
});

app.get('/updateusershowlocation', async (req, res) => {
    const {username,showNodesLocationByDefault} = req.query
    console.log(username,showNodesLocationByDefault)
    const result = await pool.query('UPDATE users SET showNodesLocationByDefault=$1 WHERE username=$2', [showNodesLocationByDefault, username]);
    res.json({ res: 'User updated'});
});

app.get('/updatenodeisfavourite', async (req, res) => {
    const {unid,isfavourite} = req.query
    console.log(unid,isfavourite)
    await pool.query('UPDATE meter_settings SET isfavourite=$1 WHERE unid=$2 returning *', [isfavourite, unid]);
    res.json({ res: 'Node updated'});
});

app.get('/updateuserdefaultstartwindow', async (req, res) => {
    const {username,defaultstartwindow} = req.query
    console.log(username,defaultstartwindow)
    const result = await pool.query('UPDATE users SET defaultstartwindow=$1 WHERE username=$2', [defaultstartwindow, username]);
    res.json({ res: 'defaultstartwindow updated'});
});

app.get('/updateuserexpandSidePanelOnEditMode', async (req, res) => {
    const {username,expandSidePanelOnEditMode} = req.query
    console.log(username,expandSidePanelOnEditMode)
    const result = await pool.query('UPDATE users SET expandSidePanelOnEditMode=$1 WHERE username=$2', [expandSidePanelOnEditMode, username]);
    res.json({ res: 'expandSidePanelOnEditMode updated'});
});

app.get('/getnodes', async (req, res) => {
    const settingsResult = await pool.query('SELECT * FROM meter_settings');
    const settings = settingsResult.rows;
    const treeResult = await pool.query('SELECT * FROM treeandsettings order by id desc limit 1');
    const treeChildren = treeResult.rows[0].tree.children;
    const unidsInTree = [];
    const getAllUnidsInTree = (tree) => {
        tree.forEach(node => {
            if(node.type == 'meter'){
                const nodeunid = node.unid;
                unidsInTree.push(nodeunid);
            }
            if(node.children){
                getAllUnidsInTree(node.children);
            }
        });
    };
    getAllUnidsInTree(treeChildren);
    const validNodes = [];
    const getValidNodes = async ()=>{
        unidsInTree.forEach(unid => {
            const corrspondingSetting = settings.find(setting => setting.unid === unid);
            if(corrspondingSetting){
                validNodes.push(corrspondingSetting)
            }
        });
    }
    await getValidNodes()
    res.json({ res: 'nodes fetched', data: validNodes });
});

app.get('/meterlogfromdb', async (req, res) => {
    const result = await pool2.query('SELECT * FROM mqttmeter order by id desc limit 100');
    res.json({ res: 'meterlogfromdb', data: result.rows });
})

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});