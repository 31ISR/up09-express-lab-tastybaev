const express = require("express")
const db = require("./db.js")
const bcr = require("bcryptjs")
const jwt = require("jsonwebtoken")
const app = express()
const SECRET = "oiuyjh228💋🌹🎂"

app.use(express.json())

const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]
    if (!token) return res.status(401).json({ error: "нет такого токена" })
    try {
        const decoded = jwt.verify(token, SECRET)
        req.user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.id)
        if (!req.user) return res.status(401).json({ error: "это кто" })
        next()
    } catch {
        res.status(401).json({ error: "Токен невалидный" })
    }
}

const adminOnly = (req, res, next) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "тебе нельзя" })
    next()
}

app.post("/api/auth/register", (req, res) => {
    const { username, email, password, role } = req.body
    const hashed = bcr.hashSync(password, 10)
    const userRole = role === "admin" ? "admin" : "user"
    try {
        const result = db.prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)")
            .run(username, email, hashed, userRole)
        const user = db.prepare("SELECT id, username, email, role FROM users WHERE id = ?").get(result.lastInsertRowid)
        const token = jwt.sign({ id: user.id }, SECRET)
        res.status(201).json({ token, user })
    } catch {
        res.status(400).json({ error: "занято" })
    }
})

app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    
    if (!user || !bcr.compareSync(password, user.password)) {
        return res.status(401).json({ error: "не правильно🤣" })
    }
    
    const { password: _, ...safeUser } = user
    const token = jwt.sign({ id: user.id }, SECRET)
    res.json({ token, user: safeUser })
})

app.get("/api/auth/profile", auth, (req, res) => {
    const { password: _, ...user } = req.user
    res.json(user)
})

app.get("/api/books", (req, res) => {
    const books = db.prepare(`
        SELECT b.*, u.username as addedBy 
        FROM books b 
        LEFT JOIN users u ON b.createdBy = u.id
    `).all()
    res.json(books)
})

app.get("/api/books/:id", (req, res) => {
    const book = db.prepare(`
        SELECT b.*, u.username as addedBy 
        FROM books b 
        LEFT JOIN users u ON b.createdBy = u.id 
        WHERE b.id = ?
    `).get(req.params.id)
    if (!book) return res.status(404).json({ error: "ты че совсем" })
    const reviews = db.prepare(`
        SELECT r.*, u.username as user 
        FROM reviews r 
        JOIN users u ON r.userId = u.id 
        WHERE r.bookId = ?
    `).all(req.params.id)
    res.json({ ...book, reviews })
})

app.post("/api/books", auth, (req, res) => {
    const { title, author, year, genre, description } = req.body
    if (!title) return res.status(400).json({ error: "напиши пожалуйста" })
    const result = db.prepare(`
        INSERT INTO books (title, author, year, genre, description, createdBy) 
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(title, author, year, genre, description, req.user.id)
    const book = db.prepare("SELECT * FROM books WHERE id = ?").get(result.lastInsertRowid)
    res.status(201).json(book)
})

app.put("/api/books/:id", auth, (req, res) => {
    const book = db.prepare("SELECT * FROM books WHERE id = ?").get(req.params.id)
    if (!book) return res.status(404).json({ error: "67" })
    if (book.createdBy !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "Нет прав на машину" })
    }
    
    const { title, author, year, genre, description } = req.body
    db.prepare(`
        UPDATE books SET 
            title = COALESCE(?, title),
            author = COALESCE(?, author),
            year = COALESCE(?, year),
            genre = COALESCE(?, genre),
            description = COALESCE(?, description)
        WHERE id = ?
    `).run(title, author, year, genre, description, req.params.id)
})

app.delete("/api/books/:id", auth, (req, res) => {
    const book = db.prepare("SELECT * FROM books WHERE id = ?").get(req.params.id)
    if (!book) return res.status(404).json({ error: "нету брат" })
    if (book.createdBy !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "тебе нет" })
    }
    
    db.prepare("DELETE FROM books WHERE id = ?").run(req.params.id)
    res.json({ message: "зачем" })
})

app.post("/api/books/:id/reviews", auth, (req, res) => {
    const { rating, comment } = req.body
    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: "ты что дурак" })
    }
    
    const book = db.prepare("SELECT * FROM books WHERE id = ?").get(req.params.id)
    if (!book) return res.status(404).json({ error: "сикс севен" })
    
    try {
        const result = db.prepare("INSERT INTO reviews (bookId, userId, rating, comment) VALUES (?, ?, ?, ?)")
            .run(req.params.id, req.user.id, rating, comment)
        res.status(201).json({ message: "готово брат", id: result.lastInsertRowid })
    } catch {
        res.status(400).json({ error: "не борщи" })
    }
})

app.get("/api/books/:id/reviews", (req, res) => {
    const reviews = db.prepare(`
        SELECT r.*, u.username as user 
        FROM reviews r 
        JOIN users u ON r.userId = u.id 
        WHERE r.bookId = ?
    `).all(req.params.id)
    res.json(reviews)
})

app.delete("/api/reviews/:id", auth, (req, res) => {
    const review = db.prepare("SELECT * FROM reviews WHERE id = ?").get(req.params.id)
    if (!review) return res.status(404).json({ error: "кимваеиваеи" })
    if (review.userId !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "ааааааааааааааааа" })
    }
    
    db.prepare("DELETE FROM reviews WHERE id = ?").run(req.params.id)
    res.json({ message: "удалил только для тебя" })
})

app.get("/api/admin/users", auth, adminOnly, (req, res) => {
    const users = db.prepare("SELECT id, username, email, role, createdAt FROM users").all()
    res.json(users)
})

app.delete("/api/admin/users/:id", auth, adminOnly, (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id)
    if (!user) return res.status(404).json({ error: "нету" }) 
    db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id)
    res.json({ message: "убили марка" })
})

app.listen(1337)
