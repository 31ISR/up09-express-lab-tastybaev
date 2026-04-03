const express = require('express')
const { hash } = require('node:crypto')
const bcr = require('bcrypt')
const db = require('./db.js')
const app = express()

app.use(express.json())
const port = 3000



app.get('/', (req, res) => {
  res.send('Hello World!')
})


function auth(req, res, next ){
  const token = req.headers.autorization; 
  if (!token){
    return res.status(401).json({message: "no autorization"})
  }
  const user = db.prepare('SELECT * FROM users WHERE tpken = ?').get(token);
  if (!user){
    return res.status (401).json ({message:"not token"});
  }
  req.user=user;
  next();
}

app.post("/api/auth/login", (req,res)=>{
    try{
        const{email,password}=req.body

        if(!email||!password)
            return res
        .status(400)
        .json({error:"Missing fields"})

        const user = db
        .prepare('SELECT * FROM users WHERE email = ?')
        .get(email)
        if (!user) return res
        .status(401)
        .json({error:"wrong password"})

    } catch(error){
        console.error(error)
        res 
            .status(500)
            .json({error: "Spomething went wrong"})
    }
})


app.post("/api/auth/register", (req,res)=>{
  try{
  const{email, username, password} = req.body

        if(!email || !username || !password)
            return res
        .status(400)
        .json({error: "Missing fields"})
      const salt = bcr.genSaltSync(10);
      const hash = bcr.hashSync(password, salt);
   const user = db.prepare('INSERT INTO users (email, username, password) VALUES (?, ?, ?)')
   .run(email, username, hash)
        const {password:_, ...safeUser} = user
         return res.status(201).json(safeUser)  
    } catch(error){
        console.error(error)
        res
          .status(500)
          .json({error: "something went wrong "})
            
    }})

// прикрепляем пользователя к запросу

function checkRole(...allowedRoles) {
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

app.post('/users', auth, checkRole('admin'), (req, res) => {
 try{
        const{email, username, password} = req.body

        if(!email || !username || !password)
            return res
        .status(400)
        .json({error: "Missing fields"})
        const info =db.prepare('INSERT INTO users (email, username, password VALUES(?, ?, ?)')
        .run(email, username, hash)
        const salt = bcr.genSaltSync(10)
        const hash = bcr.hashSync(password, salt)            
        const users = db.prepare("SELECT * FROM users WHERE id = ?")
        .get(info.lastInsertRowid)
    

        const {password:_, ...safeUser} = users
         return res.status(201).json(safeUser)  
    } catch(error){
        console.error(error)
        res
            .status(500)
            .json({error: "something went wrong "})
    }
})



app.get('/api/auth/profile', (req, res) => {
  try{
  const{email, name, password} = req.body

        if(!email || !name || !password)
            return res
        .status(400)
        .json({error: "Missing fields"})
      const salt = bcr.genSaltSync(10);
      const hash = bcr.hashSync(password, salt);
     const info = db.prepare('INSERT INTO users (email, name, password) VALUES (?, ?, ?)')
        .run(email, name, hash);
      const user = db.prepare('SELECT * FROM users WHERE id = ?')
        .get(info.lastInsertRowid)
        .run(info.lastInsertRowid)            

        const {password:_, ...safeUser} = user
         return res.status(201).json(safeUser)  
    } catch(error){
        console.error(error)
        res
          .status(500)
          .json({error: "something went wrong "})
            
    }})

app.get('books', auth, checkRole('admin'), (req, res) => {
 try{
        const{title, year, genre, description, author, user_id } = req.body

        if(!title || !year || !genre || !description || !author || !user_id)
            return res
        .status(400)
        .json({error: "Missing fields"})
        const info = db.prepare('INSERT INTO books (title, year, genre, description, author, user_id) VALUES (?, ?, ?, ?, ?, ?)')
        
        .run(title, year, genre, description, author, user_id)
        .prepare("SELECT * FROM users WHERE id = ?")
        .run(info.lastInsertRowid)               
}
finally{}
})


app.get('/reviews', auth, checkRole('admin'), (req, res)=>{
  try{
    const{bookid, userid, rating, comment} = req.body
    if(!bookid || !userid || !rating|| !comment)
      return res
    .status(400)
    .json({error: "Missing fields"})
    const info = db.prepare('INSERT INTO reviews (bookid, userid, rating, comment) VALUES (?, ?, ?, ?)')
    .run(bookid, userid, rating, comment)
    .prepare("SELECT * FROM reviews id= ?")
    .run(info.lastInsertRowid)
  }
  finally{}
})



app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})