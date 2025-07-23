// backend/index.js

const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Cấu hình ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const DATABASE_URL = process.env.DATABASE_URL;

if (!GOOGLE_CLIENT_ID || !DATABASE_URL) {
    console.error("FATAL ERROR: GOOGLE_CLIENT_ID or DATABASE_URL environment variable is not set.");
    process.exit(1);
}

const authClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const mongoClient = new MongoClient(DATABASE_URL, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;
let keysCollection;

// Kết nối đến MongoDB
mongoClient.connect().then(() => {
    console.log("Successfully connected to MongoDB Atlas!");
    db = mongoClient.db("api_key_manager");
    keysCollection = db.collection("keys");
}).catch(err => {
    console.error("Failed to connect to MongoDB Atlas", err);
    process.exit(1);
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
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// --- HEALTH CHECK ENDPOINT ---
app.get('/api/health', (req, res) => {
  const isMongoConnected = mongoClient?.topology?.isConnected();

  if (isMongoConnected) {
    res.status(200).json({
      status: 'OK',
      message: 'Server is running and database connection is healthy.'
    });
  } else {
    res.status(503).json({
      status: 'SERVICE_UNAVAILABLE',
      message: 'Server is running, but database connection is lost.'
    });
  }
});

// --- API Endpoints ---

app.get('/api/keys', authMiddleware, async (req, res) => {
    try {
        const keys = await keysCollection.find({ user_id: req.userId }).toArray();
        res.json(keys);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/keys', authMiddleware, async (req, res) => {
    try {
        const newKey = { ...req.body, user_id: req.userId };
        const result = await keysCollection.insertOne(newKey);
        res.status(201).json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// --- FIX: Endpoint cập nhật đã được sửa để xử lý tất cả các trường ---
app.put('/api/keys/:id', authMiddleware, async (req, res) => {
    // Lấy tất cả các trường có thể được cập nhật từ body của request
    const { name, notes, favorite, order } = req.body;
    
    // Kiểm tra xem có ít nhất một trường được cung cấp để cập nhật không
    if (name === undefined && notes === undefined && favorite === undefined && order === undefined) {
        return res.status(400).json({ error: "At least one field (name, notes, favorite, order) is required for update." });
    }

    const updateFields = {};
    // Thêm các trường vào đối tượng update nếu chúng tồn tại trong request
    if (name !== undefined) {
        updateFields.name = name;
    }
    if (notes !== undefined) {
        updateFields.notes = notes;
    }
    if (order !== undefined) {
        updateFields.order = order;
    }
    if (favorite !== undefined) {
        if (typeof favorite !== 'boolean') {
            return res.status(400).json({ error: "favorite field must be a boolean." });
        }
        updateFields.favorite = favorite;
    }

    try {
        const result = await keysCollection.updateOne(
            { id: req.params.id, user_id: req.userId },
            { $set: updateFields } // Sử dụng đối tượng update đã được xây dựng đầy đủ
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Key not found or user not authorized" });
        }
        res.json({ message: 'Updated successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.delete('/api/keys/:id', authMiddleware, async (req, res) => {
    try {
        const result = await keysCollection.deleteOne({ id: req.params.id, user_id: req.userId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Key not found or user not authorized" });
        }
        res.status(204).send();
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
