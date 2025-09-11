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

// Modify validateuser endpoint to include roles in response
app.post('/validateuser', async (req, res) => {
    const {username, password, rememberme} = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
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

// Add User
app.post('/adduser', async (req, res) => {
    const { username, password, email, mobile, name, role, location, roles } = req.body;
    
    if (!username || !password || !email || !mobile) {
        return res.status(400).json({ res: 'error', message: 'All fields are required' });
    }

    try {
        // First check if email exists
        const existingEmail = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
        if (existingEmail.rowCount > 0) {
            return res.json({ res: 'email exists' });
        }

        // Then check if username exists
        const existingUser = await pool.query('SELECT username FROM users WHERE username = $1', [username]);
        if (existingUser.rowCount > 0) {
            return res.json({ res: 'username exists' });
        }

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, email, role, created_at, mobilenumber, name, location, roles) 
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour', $5, $6, $7, $8::jsonb) 
             RETURNING id, username, email, role, created_at`,
            [username, passwordHash, email, role, mobile, name, location, JSON.stringify(roles)]
        );
        
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
        res.status(500).json({ res: 'error', message: 'Server error creating user' });
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
    changes.forEach(async (change) => {
        const query = change[0];
        const values = change[1];
        try {
            await pool.query(query, values);
        } catch (error) {
            console.error('Error updating meter settings:', error);
            res.status(500).json({ success: false, message: 'Error updating settings', error: error.message });
        }
    });
    res.json({ res: 'Settings updated'});
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