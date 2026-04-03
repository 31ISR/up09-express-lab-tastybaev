const Database = require('better-sqlite3');
const { appendFile } = require('node:fs');
const db = new Database('library.db');

// Включаем поддержку внешних ключей
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' ,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    year INTEGER NOT NULL,
    genre TEXT NOT NULL,
    description TEXT NOT NULL,
    author TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    createdBy INTEGER NOT NULL,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS reviews(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bookid INTEGER NOT NULL,
  userid INTEGER NOT NULL,
  rating INTEGER NOT NULL,
  comment TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)
  `);

  module.exports=db