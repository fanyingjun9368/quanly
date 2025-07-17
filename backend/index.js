// backend/index.js

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { OAuth2Client } = require('google-auth-library');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Cấu hình ---
// Bạn sẽ cần đặt biến này trong Environment Variables trên Render
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID; 
if (!GOOGLE_CLIENT_ID) {
    console.error("FATAL ERROR: GOOGLE_CLIENT_ID environment variable is not set.");
    process.exit(1); // Thoát ứng dụng nếu thiếu cấu hình
}
const authClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// --- Thiết lập cơ sở dữ liệu SQLite ---
// Đảm bảo thư mục 'data' tồn tại trên Render
const dbPath = path.join(__dirname, 'data');
if (!fs.existsSync(dbPath)) {
    fs.mkdirSync(dbPath);
}
const db = new sqlite3.Database(path.join(dbPath, 'apikeys.db'), (err) => {
    if (err) {
        console.error("Error opening database", err.message);
    } else {
        console.log("Database connected successfully.");
        db.run(`CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            type TEXT NOT NULL,
            notes TEXT,
            status TEXT,
            status_message TEXT,
            created_at TEXT NOT NULL
        )`);
    }
});

// --- Middlewares ---
app.use(cors());
app.use(express.json());

async function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    const token = authHeader.split(' ')[1];

    try {
        const ticket = await authClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        req.userId = payload['sub'];
        next();
    } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// --- API Endpoints ---
app.get('/api/keys', authMiddleware, (req, res) => {
    db.all("SELECT * FROM api_keys WHERE user_id = ?", [req.userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

app.post('/api/keys', authMiddleware, (req, res) => {
    const { id, name, value, type, notes, status, status_message, created_at } = req.body;
    const sql = `INSERT INTO api_keys (id, user_id, name, value, type, notes, status, status_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(sql, [id, req.userId, name, value, type, notes, status, status_message, created_at], function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        res.status(201).json({ id: id });
    });
});

app.put('/api/keys/:id', authMiddleware, (req, res) => {
    const { notes } = req.body; // Chỉ cho phép cập nhật ghi chú
    if (notes === undefined) {
        return res.status(400).json({ error: "Only 'notes' field can be updated." });
    }
    const sql = `UPDATE api_keys SET notes = ? WHERE id = ? AND user_id = ?`;
    db.run(sql, [notes, req.params.id, req.userId], function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "Key not found or user not authorized" });
        }
        res.json({ message: 'Updated successfully' });
    });
});

app.delete('/api/keys/:id', authMiddleware, (req, res) => {
    const sql = `DELETE FROM api_keys WHERE id = ? AND user_id = ?`;
    db.run(sql, [req.params.id, req.userId], function(err) {
        if (err) {
            res.status(400).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "Key not found or user not authorized" });
        }
        res.status(204).send(); // No Content
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
