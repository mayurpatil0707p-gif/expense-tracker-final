const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.get('/reset-password.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/reset-password.html'));
});

// ============ DATABASE SETUP ============
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// Create tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password TEXT NOT NULL,
            profilePic TEXT,
            resetToken TEXT,
            resetTokenExpiry INTEGER,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            userId TEXT NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            notes TEXT,
            date DATETIME NOT NULL,
            isRecurring INTEGER DEFAULT 0,
            recurringPeriod TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    console.log('✅ Database ready');
});

// Helper functions
function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function allQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// ============ EMAIL SETUP ============
const EMAIL_USER = 'mayurpatil0707p@gmail.com';
const EMAIL_PASS = 'bvovxhoxgetgdqaz';

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// ============ FILE UPLOAD ============
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// ============ AUTH MIDDLEWARE ============
function auth(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        const decoded = jwt.verify(token, 'secret_key_2024');
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// ============ ADMIN PASSWORD PROTECTION ============
const ADMIN_PASSWORD = '1234567890';  // Your admin password

function checkAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Admin Access"');
        return res.status(401).send('Authentication required');
    }
    
    const base64 = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64, 'base64').toString('utf8');
    const [username, password] = credentials.split(':');
    
    if (password === ADMIN_PASSWORD) {
        return next();
    }
    
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Access"');
    return res.status(401).send('Invalid password');
}

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        const existing = await getQuery('SELECT id FROM users WHERE email = ?', [email]);
        if (existing) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const id = Date.now().toString();
        
        await runQuery(
            'INSERT INTO users (id, name, email, phone, password) VALUES (?, ?, ?, ?, ?)',
            [id, name, email, phone || '', hashedPassword]
        );
        
        const token = jwt.sign({ userId: id }, 'secret_key_2024');
        
        res.json({
            message: 'User created successfully',
            token,
            user: { id, name, email, phone: phone || '', profilePic: '' }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await getQuery('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
        
        const token = jwt.sign({ userId: user.id }, 'secret_key_2024');
        
        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, phone: user.phone || '', profilePic: user.profilePic || '' }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await getQuery('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(404).json({ error: 'Email not found' });
        
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;
        
        await runQuery('UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE id = ?', [resetToken, resetTokenExpiry, user.id]);
        
        const resetLink = `https://expense-tracker-final-s9rs.onrender.com/reset-password.html?token=${resetToken}`;
        
        const emailHTML = `
            <h1>Reset Password</h1>
            <p>Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>
        `;
        
        await transporter.sendMail({
            from: `"SmartFinance" <${EMAIL_USER}>`,
            to: email,
            subject: 'Reset Password',
            html: emailHTML
        });
        
        res.json({ message: 'Reset link sent to your email!' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

// Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await getQuery('SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?', [token, Date.now()]);
        if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
        
        const hashed = await bcrypt.hash(newPassword, 10);
        await runQuery('UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?', [hashed, user.id]);
        
        res.json({ message: 'Password reset successful!' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Update Name
app.put('/api/profile/update-name', auth, async (req, res) => {
    try {
        const { name } = req.body;
        await runQuery('UPDATE users SET name = ? WHERE id = ?', [name, req.userId]);
        res.json({ name });
    } catch (error) {
        res.status(500).json({ error: 'Update failed' });
    }
});

// Upload Profile Picture
app.post('/api/profile/upload-pic', auth, upload.single('profilePic'), async (req, res) => {
    try {
        const profilePicUrl = `https://expense-tracker-final-s9rs.onrender.com/uploads/${req.file.filename}`;
        await runQuery('UPDATE users SET profilePic = ? WHERE id = ?', [profilePicUrl, req.userId]);
        res.json({ profilePic: profilePicUrl });
    } catch (error) {
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Get Transactions
app.get('/api/transactions', auth, async (req, res) => {
    try {
        const transactions = await allQuery('SELECT * FROM transactions WHERE userId = ? ORDER BY date DESC', [req.userId]);
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Add Transaction
app.post('/api/transactions', auth, async (req, res) => {
    try {
        const { amount, type, category, description, date, notes } = req.body;
        const id = Date.now().toString();
        
        await runQuery(
            `INSERT INTO transactions (id, userId, amount, type, category, description, notes, date, isRecurring)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, req.userId, amount, type, category, description, notes || '', date || new Date().toISOString(), 0]
        );
        
        const newTransaction = await getQuery('SELECT * FROM transactions WHERE id = ?', [id]);
        res.status(201).json(newTransaction);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete Transaction
app.delete('/api/transactions/:id', auth, async (req, res) => {
    try {
        await runQuery('DELETE FROM transactions WHERE id = ? AND userId = ?', [req.params.id, req.userId]);
        res.json({ message: 'Transaction deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Delete error' });
    }
});

// Send Email Report
app.post('/api/send-report', auth, async (req, res) => {
    try {
        const { userEmail, userName, totalBalance, totalIncome, totalExpense, incomeCount, expenseCount, transactions, currencySymbol } = req.body;
        
        let table = '<table border="1" cellpadding="8"><tr><th>Date</th><th>Description</th><th>Category</th><th>Amount</th></tr>';
        transactions.forEach(t => {
            table += `<tr><td>${new Date(t.date).toLocaleDateString()}</td><td>${t.description}</td><td>${t.category}</td><td>${t.type === 'income' ? '+' : '-'}${currencySymbol}${t.amount}</td></tr>`;
        });
        table += '</table>';
        
        const html = `
            <h1>Financial Report</h1>
            <p>Hello ${userName},</p>
            <h2>Summary</h2>
            <p>Total Balance: ${currencySymbol}${totalBalance}</p>
            <p>Total Income: ${currencySymbol}${totalIncome} (${incomeCount} transactions)</p>
            <p>Total Expense: ${currencySymbol}${totalExpense} (${expenseCount} transactions)</p>
            <h2>Transactions</h2>
            ${table}
            <p>SmartFinance Tracker</p>
        `;
        
        await transporter.sendMail({
            from: `"SmartFinance" <${EMAIL_USER}>`,
            to: userEmail,
            subject: `Financial Report - ${new Date().toLocaleDateString()}`,
            html
        });
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send email' });
    }
});

// Serve uploaded files
app.use('/uploads', express.static(uploadDir));

// ============ ADMIN PANEL - PASSWORD PROTECTED ============
app.get('/admin', checkAuth, async (req, res) => {
    try {
        // Get all users
        const users = await allQuery('SELECT id, name, email, phone, createdAt FROM users ORDER BY createdAt DESC');
        
        // Get selected user (from query parameter)
        const selectedUserId = req.query.user;
        
        // Get transactions for selected user
        let selectedUser = null;
        let userTransactions = [];
        
        if (selectedUserId) {
            selectedUser = await allQuery('SELECT id, name, email, phone, createdAt FROM users WHERE id = ?', [selectedUserId]);
            selectedUser = selectedUser[0];
            userTransactions = await allQuery('SELECT * FROM transactions WHERE userId = ? ORDER BY date DESC', [selectedUserId]);
        }
        
        // Calculate totals for selected user
        let totalIncome = 0;
        let totalExpense = 0;
        let incomeCount = 0;
        let expenseCount = 0;
        
        userTransactions.forEach(t => {
            if (t.type === 'income') {
                totalIncome += t.amount;
                incomeCount++;
            } else {
                totalExpense += t.amount;
                expenseCount++;
            }
        });
        
        const balance = totalIncome - totalExpense;
        
        // Generate HTML
        let html = `
<!DOCTYPE html>
<html>
<head>
    <title>SmartFinance - Admin Panel</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            color: white;
            margin-bottom: 10px;
            text-align: center;
            font-size: 32px;
        }
        .subtitle {
            color: rgba(255,255,255,0.8);
            text-align: center;
            margin-bottom: 30px;
        }
        .back-link {
            display: inline-block;
            background: white;
            color: #667eea;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            margin-bottom: 20px;
        }
        .back-link:hover {
            background: #f0f0f0;
        }
        
        /* Users Grid */
        .users-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .user-card {
            background: white;
            border-radius: 20px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .user-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .user-card.selected {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
        }
        .user-card.selected .user-email,
        .user-card.selected .user-phone {
            color: rgba(255,255,255,0.8);
        }
        .user-name {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .user-email {
            font-size: 14px;
            color: #666;
            margin-bottom: 5px;
        }
        .user-phone {
            font-size: 12px;
            color: #999;
        }
        .user-date {
            font-size: 11px;
            color: #aaa;
            margin-top: 10px;
        }
        
        /* Stats for selected user */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #666;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: bold;
        }
        .income-number {
            color: #4caf50;
        }
        .expense-number {
            color: #ff6b6b;
        }
        .balance-number {
            color: #667eea;
        }
        
        /* Transactions Table */
        .section {
            background: white;
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover {
            background: #f8f9ff;
        }
        .income {
            color: #4caf50;
            font-weight: bold;
        }
        .expense {
            color: #ff6b6b;
            font-weight: bold;
        }
        .empty-message {
            text-align: center;
            color: #999;
            padding: 40px;
        }
        .footer {
            text-align: center;
            color: rgba(255,255,255,0.8);
            margin-top: 30px;
            padding: 20px;
            font-size: 12px;
        }
        .no-selection {
            text-align: center;
            color: #999;
            padding: 60px;
            background: white;
            border-radius: 20px;
        }
        @media (max-width: 768px) {
            .users-grid {
                grid-template-columns: 1fr;
            }
            th, td { font-size: 12px; padding: 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← Back to App</a>
        <h1>💰 SmartFinance - Admin Panel</h1>
        <div class="subtitle">Click on any user to view their transactions</div>
        
        <div class="users-grid">
            ${users.map(user => `
                <div class="user-card ${selectedUserId === user.id ? 'selected' : ''}" onclick="window.location.href='/admin?user=${user.id}'">
                    <div class="user-name">👤 ${user.name}</div>
                    <div class="user-email">📧 ${user.email}</div>
                    <div class="user-phone">📞 ${user.phone || 'No phone'}</div>
                    <div class="user-date">📅 Joined: ${new Date(user.createdAt).toLocaleDateString()}</div>
                </div>
            `).join('')}
        </div>
        
        ${selectedUserId && selectedUser ? `
            <div class="stats">
                <div class="stat-card">
                    <h3>💰 Total Balance</h3>
                    <div class="number balance-number">₹${balance.toFixed(2)}</div>
                </div>
                <div class="stat-card">
                    <h3>📈 Total Income</h3>
                    <div class="number income-number">₹${totalIncome.toFixed(2)}</div>
                    <div style="font-size: 12px; color: #666;">${incomeCount} transactions</div>
                </div>
                <div class="stat-card">
                    <h3>📉 Total Expense</h3>
                    <div class="number expense-number">₹${totalExpense.toFixed(2)}</div>
                    <div style="font-size: 12px; color: #666;">${expenseCount} transactions</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Transactions of ${selectedUser.name}</h2>
                ${userTransactions.length === 0 ? '<div class="empty-message">No transactions yet. User hasn\'t added any income or expense.</div>' : `
                    <table>
                        <thead>
                            <tr><th>Date</th><th>Description</th><th>Category</th><th>Type</th><th>Amount</th><th>Notes</th></tr>
                        </thead>
                        <tbody>
                            ${userTransactions.map(t => `
                                <tr>
                                    <td>${new Date(t.date).toLocaleDateString()}</td>
                                    <td>${t.description}</td>
                                    <td>${t.category}</td>
                                    <td class="${t.type}">${t.type === 'income' ? '💰 Income' : '💸 Expense'}</td>
                                    <td class="${t.type}">${t.type === 'income' ? '+' : '-'}₹${t.amount}</td>
                                    <td>${t.notes || '-'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `}
            </div>
        ` : `
            <div class="no-selection">
                <h3>Select a user from above</h3>
                <p>Click on any user card to view their transactions, income, and expense details.</p>
            </div>
        `}
        
        <div class="footer">
            <p>📁 Database Location: /opt/render/project/src/backend/database.db</p>
            <p>🕒 Last Updated: ${new Date().toLocaleString()}</p>
            <p>SmartFinance Tracker - Each user's data is stored separately in SQLite database</p>
        </div>
    </div>
</body>
</html>
        `;
        res.send(html);
    } catch (error) {
        res.send(`<h1>Error</h1><p>${error.message}</p>`);
    }
});

// ============ START SERVER ============
app.listen(process.env.PORT || 5000, () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 5000}`);
    console.log(`✅ Database: ${dbPath}`);
});