require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'change_this_secret';
const PORT = process.env.PORT || 5000;

// DB
const dbFile = path.join(__dirname, 'data.db');
const db = new sqlite3.Database(dbFile);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT)`);
});

// Uploads folder
const UPLOADS = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage });

function genToken(user){ return jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET, { expiresIn: '7d' }); }
function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({ error: 'Missing token' });
  const token = h.split(' ')[1];
  try { const data = jwt.verify(token, SECRET); req.user = data; next(); } catch(err){ return res.status(401).json({ error: 'Invalid token' }); }
}

// Routes
app.get('/', (req,res) => res.send('Harshdeep backend ready'));

// Register
app.post('/api/auth/register', async (req,res) => {
  const { name, email, password } = req.body || {};
  if(!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hashed = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users(name,email,password) VALUES(?,?,?)', [name,email,hashed], function(err){
    if(err) return res.status(400).json({ error: err.message });
    const user = { id: this.lastID, name, email };
    const token = genToken(user);
    res.json({ user, token });
  });
});

// Login
app.post('/api/auth/login', (req,res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id,name,email,password FROM users WHERE email = ?', [email], async (err,row) => {
    if(err) return res.status(500).json({ error: err.message });
    if(!row) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password || '');
    if(!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const user = { id: row.id, name: row.name, email: row.email };
    const token = genToken(user);
    res.json({ user, token });
  });
});

// Protected content (BCA guide)
app.get('/api/content', authMiddleware, (req,res) => {
  const p = path.join(__dirname, '..', 'content', 'BCA_content.md');
  if(fs.existsSync(p)) res.sendFile(p);
  else res.status(404).send('Content not found');
});

// Examples list (protected)
const examples = [
  { id: 'calc', title: 'Calculator', lang:'JS', source: `<!doctype html><html><body style="font-family:Arial;padding:10px"><h3>Calculator</h3><input id="a" placeholder="Number A"/><input id="b" placeholder="Number B"/><br/><button onclick="op('+')">+</button><button onclick="op('-')">-</button><button onclick="op('*')">*</button><button onclick="op('/')">/</button><div id="out"></div><script>function op(op){var a=parseFloat(document.getElementById('a').value||0);var b=parseFloat(document.getElementById('b').value||0);var r=0;if(op=='+')r=a+b;else if(op=='-')r=a-b;else if(op=='*')r=a*b;else r=(b===0?'Infinity':a/b);document.getElementById('out').innerText='Result: '+r;}</script></body></html>` },
  { id: 'todo', title: 'To-Do', lang:'JS', source: `<!doctype html><html><body style="font-family:Arial;padding:10px"><h3>ToDo</h3><input id="t"/><button onclick="add()">Add</button><ul id="list"></ul><script>function render(){var items=JSON.parse(localStorage.getItem('td')||'[]');var ul=document.getElementById('list');ul.innerHTML='';items.forEach((it,i)=>{var li=document.createElement('li');li.textContent=it;var b=document.createElement('button');b.textContent='Del';b.onclick=function(){items.splice(i,1);localStorage.setItem('td',JSON.stringify(items));render();};li.appendChild(b);ul.appendChild(li);});}function add(){var t=document.getElementById('t').value;if(!t)return;var items=JSON.parse(localStorage.getItem('td')||'[]');items.push(t);localStorage.setItem('td',JSON.stringify(items));document.getElementById('t').value='';render();}render();</script></body></html>` }
];

app.get('/api/examples', authMiddleware, (req,res) => res.json(examples));

// Upload (protected)
app.post('/api/upload', authMiddleware, upload.single('file'), (req,res) => {
  if(!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ message: 'Uploaded', file: { filename: req.file.filename, original: req.file.originalname, url: '/uploads/' + req.file.filename } });
});

// Serve uploads
app.use('/uploads', express.static(UPLOADS));

app.listen(PORT, () => console.log('Server listening on', PORT));
