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
        
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Date.now() + 3600000;
        
        await runQuery('UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE id = ?', [token, expiry, user.id]);
        
        const link = `https://expense-tracker-final.onrender.com/reset-password.html?token=${token}`;
        
        await transporter.sendMail({
            from: `"SmartFinance" <${EMAIL_USER}>`,
            to: email,
            subject: 'Reset Password',
            html: `<h1>Reset Password</h1><p>Click <a href="${link}">here</a> to reset your password. This link expires in 1 hour.</p>`
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
        const url = `https://expense-tracker-final.onrender.com/uploads/${req.file.filename}`;
        await runQuery('UPDATE users SET profilePic = ? WHERE id = ?', [url, req.userId]);
        res.json({ profilePic: url });
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

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ Database: ${dbPath}`);
});