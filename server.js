require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vlc_reing_secret_key_2024';

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '1234',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'vlc_web',
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const audioMime = ['audio/mpeg','audio/mp3','audio/wav','audio/ogg','audio/flac','audio/aac','audio/x-m4a','audio/mp4'];
    if (audioMime.includes(file.mimetype) || file.originalname.match(/\.(mp3|wav|ogg|flac|aac|m4a|mp4)$/i)) {
      cb(null, true);
    } else {
      cb(new Error('Solo archivos de audio permitidos'), false);
    }
  }
});

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Token requerido' });
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, display_name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    const exists = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (exists.rows.length) return res.status(400).json({ error: 'El usuario ya existe' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password, display_name) VALUES ($1, $2, $3) RETURNING id, username, display_name',
      [username, hash, display_name || username]
    );
    const token = jwt.sign({ id: result.rows[0].id, username: result.rows[0].username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(400).json({ error: 'Usuario no encontrado' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Contraseña incorrecta' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name } });
  } catch (err) {
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

app.get('/api/user', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, display_name FROM users WHERE id = $1', [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

app.post('/api/songs', auth, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Archivo de audio requerido' });
    const title = req.body.title || path.parse(req.file.originalname).name;
    const result = await pool.query(
      'INSERT INTO songs (user_id, title, filename, filepath) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, title, req.file.filename, req.file.path]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al subir canción' });
  }
});

app.get('/api/songs', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM songs WHERE user_id = $1 ORDER BY uploaded_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: 'Error al obtener canciones' });
  }
});

app.delete('/api/songs/:id', auth, async (req, res) => {
  try {
    const song = await pool.query('SELECT * FROM songs WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (!song.rows.length) return res.status(404).json({ error: 'Canción no encontrada' });
    if (fs.existsSync(song.rows[0].filepath)) fs.unlinkSync(song.rows[0].filepath);
    await pool.query('DELETE FROM history WHERE song_id = $1', [req.params.id]);
    await pool.query('DELETE FROM songs WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Error al eliminar canción' });
  }
});

app.post('/api/history', auth, async (req, res) => {
  try {
    const { song_id, title } = req.body;
    const result = await pool.query(
      'INSERT INTO history (user_id, song_id, title) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, song_id || null, title || 'Desconocido']
    );
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: 'Error al guardar historial' });
  }
});

app.get('/api/history', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM history WHERE user_id = $1 ORDER BY played_at DESC LIMIT 20',
      [req.user.id]
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
