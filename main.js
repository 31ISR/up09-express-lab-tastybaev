const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db.js');  

const app = express();
const port = 3000;

app.use(express.json());

const JWT_SECRET = 'supersecretkey_bookapi_2026';


const auth = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        const user = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?')
            .get(decoded.id);

        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        req.user = user;
        next();
    } catch (err) {
        console.error("JWT error:", err.message);
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};

const checkRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Пользователь не авторизован' });
        }
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Доступ запрещен: недостаточно прав' });
        }
        next();
    };
};



app.get('/', (req, res) => {
    res.send('Book API is running!');
});


app.post("/api/auth/register", (req, res) => {
    try {
        const { email, username, password } = req.body;

        if (!email || !username || !password) {
            return res.status(400).json({ error: "Missing fields" });
        }

        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (existing) {
            return res.status(409).json({ error: "User with this email already exists" });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);

        const result = db.prepare(`
            INSERT INTO users (username, email, password, role) 
            VALUES (?, ?, ?, 'user')
        `).run(username, email, hashedPassword);

        const newUser = db.prepare(`
            SELECT id, username, email, role, createdAt 
            FROM users WHERE id = ?
        `).get(result.lastInsertRowid);

        res.status(201).json({ 
            success: true, 
            message: "User registered successfully",
            user: newUser 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong" });
    }
});

app.post("/api/auth/login", (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({ error: "Missing email or password" });
        }

        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const isValid = bcrypt.compareSync(password, user.password || '');
        if (!isValid) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        const { password: _, ...safeUser } = user;

        res.json({
            success: true,
            token,
            user: safeUser
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Something went wrong" });
    }
});

app.get("/api/auth/profile", auth, (req, res) => {
    res.json({ success: true, user: req.user });
});


app.get("/api/books", (req, res) => {
    try {
        const books = db.prepare(`
            SELECT b.*, u.username as added_by 
            FROM books b 
            LEFT JOIN users u ON b.createdBy = u.id
        `).all();
        res.json(books);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Something went wrong" });
    }
});

// POST /api/books — Создать новую книгу
app.post("/api/books", auth, (req, res) => {
    try {
        const { title, author, year, genre, description } = req.body;

        if (!title || !author) {
            return res.status(400).json({ error: "Title and author are required" });
        }

        // createdBy берём из токена (авторизованный пользователь)
        const result = db.prepare(`
            INSERT INTO books (title, author, year, genre, description, createdBy)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(title, author, year || null, genre || null, description || null, req.user.id);

        const newBook = db.prepare(`
            SELECT b.*, u.username as added_by 
            FROM books b
            LEFT JOIN users u ON b.createdBy = u.id
            WHERE b.id = ?
        `).get(result.lastInsertRowid);

        res.status(201).json({ 
            success: true, 
            message: "Book created successfully",
            book: newBook 
        });
    } catch (error) {
        console.error("Create book error:", error);
        res.status(500).json({ error: "Something went wrong" });
    }
});


app.get("/api/books/:id", (req, res) => {
    try {
        const bookId = parseInt(req.params.id);

        if (!bookId) {
            return res.status(400).json({ error: "Invalid book ID" });
        }

        
        const book = db.prepare(`
            SELECT 
                b.id,
                b.title,
                b.author,
                b.year,
                b.genre,
                b.description,
                b.createdAt,
                u.username as added_by
            FROM books b
            LEFT JOIN users u ON b.createdBy = u.id
            WHERE b.id = ?
        `).get(bookId);

        if (!book) {
            return res.status(404).json({ error: "Book not found" });
        }

        // Получаем все отзывы к этой книге
        const reviews = db.prepare(`
            SELECT 
                r.id,
                r.rating,
                r.comment,
                r.createdAt,
                u.username as reviewer
            FROM reviews r
            JOIN users u ON r.userId = u.id
            WHERE r.bookId = ?
            ORDER BY r.createdAt DESC
        `).all(bookId);

        
        book.reviews = reviews;

        res.json(book);
    } catch (error) {
        console.error("Get book by id error:", error);
        res.status(500).json({ error: "Something went wrong" });
    }
});


app.use((err, req, res, next) => {
    console.error('=== SERVER ERROR 500 ===');
    console.error(err);
    res.status(500).json({ 
        error: "Internal Server Error",
        message: err.message 
    });
});

app.listen(port, () => {
    console.log(`Book API listening on http://localhost:${port}`);
});