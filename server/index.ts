import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import multer from 'multer';
import { z } from 'zod';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'ir-en-dark.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'visitor' CHECK(role IN ('visitor','admin')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id TEXT PRIMARY KEY,
  bio TEXT NOT NULL DEFAULT '',
  avatar_url TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_user_id TEXT NOT NULL,
  content_type TEXT NOT NULL CHECK(content_type IN ('post','comment','user')),
  content_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK(reason IN ('spam','harassment','inappropriate','malicious','other')),
  details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','reviewing','resolved','dismissed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(reporter_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_username TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_username TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admins (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_username TEXT NOT NULL,
  title TEXT,
  caption TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS post_media (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  media_url TEXT NOT NULL,
  media_type TEXT NOT NULL CHECK(media_type IN ('image','video')),
  original_name TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'visible' CHECK(status IN ('visible','hidden')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS reactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(post_id,user_id,type),
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id TEXT NOT NULL DEFAULT 'community',
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('community','direct','group')),
  title TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(conversation_id,user_id),
  FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  target_user_id TEXT,
  target_admin_username TEXT,
  post_id INTEGER,
  message_id INTEGER,
  payload TEXT,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
);
`);
db.prepare("INSERT OR IGNORE INTO conversations(id,kind,title) VALUES('community','community','IR EN DARK Community')").run();

const notificationColumns = db.prepare('PRAGMA table_info(notifications)').all() as any[];
if (!notificationColumns.some((c:any) => c.name === 'read_at')) db.exec('ALTER TABLE notifications ADD COLUMN read_at TEXT');
if (!notificationColumns.some((c:any) => c.name === 'target_admin_username')) db.exec('ALTER TABLE notifications ADD COLUMN target_admin_username TEXT');

const app = express();
app.disable('x-powered-by');

// Lightweight server-push layer. It uses the existing Express server and does not add a second realtime stack.
type RealtimeClient = { res:any; visitorId:string };
const realtimeClients = new Set<RealtimeClient>();
function pushRealtime(event:string, payload:any, audience:(c:RealtimeClient)=>boolean=()=>true) {
  const packet = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of [...realtimeClients]) {
    if (!audience(client)) continue;
    try { client.res.write(packet); } catch { realtimeClients.delete(client); }
  }
}
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(uploadDir, { maxAge: '7d', immutable: true }));

const publicLimiter = rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10, standardHeaders: true, legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 60_000, max: 40, standardHeaders: true, legacyHeaders: false });
app.use('/api', publicLimiter);

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
let ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD_HASH && ADMIN_PASSWORD) ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 12);
if (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
  console.warn('Admin auth is not configured correctly. Set JWT_SECRET (32+ chars), ADMIN_USERNAME and ADMIN_PASSWORD_HASH.');
} else {
  db.prepare('INSERT INTO admins(username,password_hash) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash').run(ADMIN_USERNAME, ADMIN_PASSWORD_HASH);
}

function cookieValue(req:any,name:string){const raw=String(req.headers.cookie||'');const part=raw.split(';').map((x:string)=>x.trim()).find((x:string)=>x.startsWith(name+'='));return part?decodeURIComponent(part.slice(name.length+1)):'';}
function adminAuth(req: any, res: any, next: any) {
  try {
    if (!JWT_SECRET) throw new Error('missing secret');
    const h = req.headers.authorization || '';
    const bearer = h.startsWith('Bearer ') ? h.slice(7) : '';
    const token = bearer || cookieValue(req,'ird_admin');
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const p = jwt.verify(token, JWT_SECRET) as any;
    if (p.role !== 'admin' || !p.sub) throw new Error('invalid role');
    const exists = db.prepare('SELECT username FROM admins WHERE username=?').get(p.sub);
    if (!exists) throw new Error('admin not found');
    req.admin = p;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin session' });
  }
}

function visitor(req: any, res: any, next: any) {
  try {
    if (!JWT_SECRET) return res.status(503).json({ error: 'Visitor sessions are not configured' });
    const token = typeof req.headers['x-visitor-token'] === 'string' ? req.headers['x-visitor-token'] : '';
    const p = jwt.verify(token, JWT_SECRET) as any;
    if (p.role !== 'visitor' || typeof p.sub !== 'string' || typeof p.name !== 'string') throw new Error('invalid visitor session');
    const id = p.sub;
    const name = p.name.trim().slice(0, 60) || 'Anonymous';
    db.prepare(`INSERT INTO users(id,display_name,role) VALUES(?,?, 'visitor') ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name`).run(id, name);
    db.prepare('INSERT OR IGNORE INTO profiles(user_id) VALUES(?)').run(id);
    req.visitorId = id; req.visitorName = name;
    next();
  } catch {
    return res.status(401).json({ error: 'Visitor session expired. Refresh the page to start a new session.' });
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => cb(null, ['image/jpeg','image/png','image/gif','image/webp','video/mp4','video/webm','video/ogg'].includes(file.mimetype))
});

function safeMedia(file: Express.Multer.File) {
  const b = file.buffer;
  const matches: Record<string, boolean> = {
    'image/jpeg': b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
    'image/png': b.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])),
    'image/gif': b.subarray(0,4).toString() === 'GIF8',
    'image/webp': b.subarray(0,4).toString() === 'RIFF' && b.subarray(8,12).toString() === 'WEBP',
    'video/mp4': b.subarray(4,8).toString() === 'ftyp',
    'video/webm': b.subarray(0,4).equals(Buffer.from([0x1a,0x45,0xdf,0xa3])),
    'video/ogg': b.subarray(0,4).toString() === 'OggS'
  };
  if (!matches[file.mimetype]) throw new Error('Media signature does not match the allowed file type');
  const extMap: Record<string,string> = {'image/jpeg':'jpg','image/png':'png','image/gif':'gif','image/webp':'webp','video/mp4':'mp4','video/webm':'webm','video/ogg':'ogv'};
  const type = file.mimetype.startsWith('image/') ? 'image' : 'video';
  const filename = `${crypto.randomUUID()}.${extMap[file.mimetype]}`;
  fs.writeFileSync(path.join(uploadDir, filename), b, { flag: 'wx' });
  return { url: `/uploads/${filename}`, type };
}

const postSchema = z.object({ title: z.string().trim().max(160).optional().or(z.literal('')), caption: z.string().trim().min(1).max(5000) });
const commentSchema = z.object({ name: z.string().trim().min(1).max(60), body: z.string().trim().min(1).max(1000) });
const reactionSchema = z.object({ type: z.enum(['like']) });
const reportSchema = z.object({contentType:z.enum(['post','comment','user']),contentId:z.union([z.string().min(1).max(80),z.number().int().positive()]).transform(String),reason:z.enum(['spam','harassment','inappropriate','malicious','other']),details:z.string().trim().max(500).optional().default('')});
const messageSchema = z.object({ name: z.string().trim().min(1).max(60), body: z.string().trim().min(1).max(2000) });

function postPayload(id: number) {
  const post = db.prepare("SELECT id,title,caption,created_at,updated_at FROM posts WHERE id=?").get(id) as any;
  if (!post) return null;
  const media = db.prepare('SELECT id,media_url,media_type,original_name FROM post_media WHERE post_id=? ORDER BY id').all(id);
  const comments = db.prepare("SELECT id,name,body,created_at FROM comments WHERE post_id=? AND status='visible' ORDER BY id ASC").all(id);
  const reactions = db.prepare('SELECT type,COUNT(*) count FROM reactions WHERE post_id=? GROUP BY type').all(id);
  return { ...post, author: 'IR EN DARK', media, comments, reactions };
}

app.post('/api/session', writeLimiter, (req,res) => {
  if (!JWT_SECRET) return res.status(503).json({error:'Visitor sessions are not configured'});
  const schema = z.object({name:z.string().trim().min(1).max(60).optional(), token:z.string().optional()});
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({error:'Invalid session details'});
  let id = crypto.randomUUID().replaceAll('-','');
  let name = (parsed.data.name || 'Anonymous').trim().slice(0,60) || 'Anonymous';
  if (parsed.data.token) {
    try {
      const old = jwt.verify(parsed.data.token, JWT_SECRET) as any;
      if (old.role === 'visitor' && typeof old.sub === 'string') { id = old.sub; name = parsed.data.name ? name : String(old.name || name).slice(0,60); }
    } catch { /* expired sessions receive a new anonymous identity */ }
  }
  db.prepare(`INSERT INTO users(id,display_name,role) VALUES(?,?, 'visitor') ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name`).run(id,name);
  db.prepare('INSERT OR IGNORE INTO profiles(user_id) VALUES(?)').run(id);
  const token = jwt.sign({role:'visitor',sub:id,name},JWT_SECRET,{expiresIn:'30d'});
  res.json({token, name, profile: db.prepare('SELECT bio,avatar_url,updated_at FROM profiles WHERE user_id=?').get(id)});
});

app.get('/api/realtime', visitor, (req:any,res:any)=>{
  res.status(200);
  res.setHeader('Content-Type','text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control','no-cache, no-transform');
  res.setHeader('Connection','keep-alive');
  res.setHeader('X-Accel-Buffering','no');
  res.flushHeaders?.();
  res.write(`event: ready\ndata: ${JSON.stringify({ok:true})}\n\n`);
  const client={res,visitorId:req.visitorId};
  realtimeClients.add(client);
  const heartbeat=setInterval(()=>{ try { res.write(`: ping ${Date.now()}\n\n`); } catch {} }, 15000);
  req.on('close',()=>{ clearInterval(heartbeat); realtimeClients.delete(client); });
});

app.post('/api/admin/login', authLimiter, async (req,res) => {
  const s = z.object({username:z.string().min(1).max(80),password:z.string().min(1).max(200)}).safeParse(req.body);
  if (!s.success || !JWT_SECRET) return res.status(401).json({error:'Invalid credentials'});
  const row = db.prepare('SELECT * FROM admins WHERE username=?').get(s.data.username) as any;
  if (!row || !(await bcrypt.compare(s.data.password,row.password_hash))) return res.status(401).json({error:'Invalid credentials'});
  const token = jwt.sign({role:'admin',sub:row.username},JWT_SECRET,{expiresIn:'2h'});
  res.setHeader('Set-Cookie', `ird_admin=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7200`); res.json({token,username:row.username});
});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({authenticated:true,username:req.admin.sub}));

app.get('/api/posts',(req,res)=>{
  const rows = db.prepare('SELECT id FROM posts ORDER BY id DESC').all() as any[];
  res.json(rows.map(x=>postPayload(x.id)));
});
app.get('/api/search',(req,res)=>{
  const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0,100) : '';
  if (!q) return res.json([]);
  const like = `%${q.replaceAll('%','\\%').replaceAll('_','\\_')}%`;
  const posts = (db.prepare("SELECT id,title,caption,created_at FROM posts WHERE title LIKE ? ESCAPE '\\' OR caption LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 20").all(like,like) as any[]).map(x=>({...x,kind:'post'}));
  const resources = (db.prepare("SELECT id,title,description AS caption,created_at,url FROM resources WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 10").all(like,like,like) as any[]).map(x=>({...x,kind:'resource'}));
  const users = (db.prepare("SELECT id,display_name AS title,bio AS caption,created_at FROM users WHERE role='visitor' AND display_name LIKE ? LIMIT 10").all(like) as any[]).map(x=>({...x,kind:'user'}));
  const topics = ['Python Basics','Variables','Conditions','Loops','Functions','Data Structures','File Handling','Python for Cyber Security','Cyber Security Basics','Web Security','Network Security','Password Security','Privacy & Security Awareness','Ethical Security','Secure Coding'].filter(t=>t.toLowerCase().includes(q.toLowerCase())).map((title,i)=>({id:`topic-${i}`,title,caption:'Learning topic',kind:'topic'}));
  res.json([...posts,...resources,...users,...topics].slice(0,40));
});

app.post('/api/posts',adminAuth,writeLimiter,upload.single('media'),(req:any,res)=>{
  const s = postSchema.safeParse({title:req.body.title||'',caption:req.body.caption||''});
  if (!s.success) return res.status(400).json({error:'Invalid post data'});
  let saved:any=null;
  try { if(req.file) saved=safeMedia(req.file); } catch(e:any) { return res.status(400).json({error:e.message||'Invalid media'}); }
  const tx=db.transaction(()=>{
    const r=db.prepare('INSERT INTO posts(author_username,title,caption) VALUES(?,?,?)').run(req.admin.sub,s.data.title||null,s.data.caption);
    const id=Number(r.lastInsertRowid);
    if(saved) db.prepare('INSERT INTO post_media(post_id,media_url,media_type,original_name) VALUES(?,?,?,?)').run(id,saved.url,saved.type,req.file.originalname.slice(0,255));
    return id;
  });
  pushRealtime('post:changed',{action:'created',post:postPayload(tx)});
  res.status(201).json(postPayload(tx));
});
app.put('/api/posts/:id',adminAuth,writeLimiter,upload.single('media'),(req:any,res)=>{
  const id=Number(req.params.id); const current=db.prepare('SELECT * FROM posts WHERE id=?').get(id) as any;
  if(!current) return res.status(404).json({error:'Post not found'});
  if(current.author_username!==req.admin.sub) return res.status(403).json({error:'Not authorized for this post'});
  const s=postSchema.safeParse({title:req.body.title||'',caption:req.body.caption||''}); if(!s.success)return res.status(400).json({error:'Invalid post data'});
  let saved:any=null; try{if(req.file)saved=safeMedia(req.file)}catch(e:any){return res.status(400).json({error:e.message||'Invalid media'})}
  db.transaction(()=>{
    db.prepare('UPDATE posts SET title=?,caption=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(s.data.title||null,s.data.caption,id);
    if(saved){const old=db.prepare('SELECT media_url FROM post_media WHERE post_id=?').get(id) as any;db.prepare('DELETE FROM post_media WHERE post_id=?').run(id);if(old?.media_url)try{fs.unlinkSync(path.join(uploadDir,path.basename(old.media_url)))}catch{};db.prepare('INSERT INTO post_media(post_id,media_url,media_type,original_name) VALUES(?,?,?,?)').run(id,saved.url,saved.type,req.file.originalname.slice(0,255));}
  })();
  pushRealtime('post:changed',{action:'updated',post:postPayload(id)});
  res.json(postPayload(id));
});
app.delete('/api/posts/:id',adminAuth,writeLimiter,(req:any,res)=>{
  const id=Number(req.params.id); const p=db.prepare('SELECT author_username FROM posts WHERE id=?').get(id) as any;
  if(!p)return res.status(404).json({error:'Post not found'}); if(p.author_username!==req.admin.sub)return res.status(403).json({error:'Not authorized for this post'});
  const media=db.prepare('SELECT media_url FROM post_media WHERE post_id=?').all(id) as any[];
  db.prepare('DELETE FROM posts WHERE id=?').run(id); for(const m of media)try{fs.unlinkSync(path.join(uploadDir,path.basename(m.media_url)))}catch{}
  pushRealtime('post:changed',{action:'deleted',postId:id});
  res.status(204).end();
});

function notify(userId:string|null,type:string,payload:any,postId:number|null=null,messageId:number|null=null){if(!userId)return;db.prepare('INSERT INTO notifications(type,target_user_id,post_id,message_id,payload) VALUES(?,?,?,?,?)').run(type,userId,postId,messageId,JSON.stringify(payload));}
function notifyAdmin(type:string,payload:any,postId:number|null=null,messageId:number|null=null){if(!ADMIN_USERNAME)return;db.prepare('INSERT INTO notifications(type,target_admin_username,post_id,message_id,payload) VALUES(?,?,?,?,?)').run(type,ADMIN_USERNAME,postId,messageId,JSON.stringify(payload));}
function notifyConversationMembers(conversationId:string,exceptId:string,type:string,payload:any,messageId:number|null=null){const users=db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>?').all(conversationId,exceptId) as any[];const stmt=db.prepare('INSERT INTO notifications(type,target_user_id,message_id,payload) VALUES(?,?,?,?)');const tx=db.transaction(()=>users.forEach(u=>stmt.run(type,u.user_id,messageId,JSON.stringify(payload))));tx();}
function notifyUsersExcept(exceptId:string|null,type:string,payload:any,messageId:number|null=null){const users=db.prepare("SELECT id FROM users WHERE role='visitor' AND id<>?").all(exceptId||'') as any[];const stmt=db.prepare('INSERT INTO notifications(type,target_user_id,message_id,payload) VALUES(?,?,?,?)');const tx=db.transaction(()=>users.forEach(u=>stmt.run(type,u.id,messageId,JSON.stringify(payload))));tx();}

app.post('/api/posts/:id/comments',visitor,writeLimiter,(req:any,res)=>{
  const s=commentSchema.safeParse(req.body);
  if(!s.success)return res.status(400).json({error:'Invalid comment'});
  const postId=Number(req.params.id);
  if(!db.prepare('SELECT id FROM posts WHERE id=?').get(postId))return res.status(404).json({error:'Post not found'});
  const r=db.prepare('INSERT INTO comments(post_id,user_id,name,body) VALUES(?,?,?,?)').run(postId,req.visitorId,req.visitorName,s.data.body);
  const comment=db.prepare("SELECT id,name,body,created_at FROM comments WHERE id=? AND status='visible'").get(Number(r.lastInsertRowid));
  notifyAdmin('comment',{postId,commentId:Number(r.lastInsertRowid)},postId);
  pushRealtime('comment:new',{postId,comment});
  res.status(201).json({id:r.lastInsertRowid,comment});
});
app.post('/api/posts/:id/reactions',visitor,writeLimiter,(req:any,res)=>{
  const s=reactionSchema.safeParse(req.body);
  if(!s.success)return res.status(400).json({error:'Invalid reaction'});
  const postId=Number(req.params.id);
  if(!db.prepare('SELECT id FROM posts WHERE id=?').get(postId))return res.status(404).json({error:'Post not found'});
  const result=db.prepare('INSERT OR IGNORE INTO reactions(post_id,user_id,type) VALUES(?,?,?)').run(postId,req.visitorId,s.data.type);
  const reactions=db.prepare('SELECT type,COUNT(*) count FROM reactions WHERE post_id=? GROUP BY type').all(postId);
  if(result.changes){ notifyAdmin('reaction',{postId,type:s.data.type,userId:req.visitorId},postId); pushRealtime('reaction:update',{postId,reactions}); }
  res.status(result.changes?201:200).json({ok:true,duplicate:!result.changes,reactions});
});

// Public profile API: only a visitor's own profile is editable; public fields are deliberately limited.
function profilePayload(id:string) {
  const profile=db.prepare('SELECT u.id,u.display_name,u.created_at,p.bio,p.avatar_url,p.updated_at FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.id=?').get(id) as any;
  if (!profile) return null;
  const activity={comments:(db.prepare('SELECT COUNT(*) n FROM comments WHERE user_id=?').get(id) as any).n,reactions:(db.prepare('SELECT COUNT(*) n FROM reactions WHERE user_id=?').get(id) as any).n,messages:(db.prepare('SELECT COUNT(*) n FROM messages WHERE user_id=?').get(id) as any).n};
  return {...profile,activity};
}
app.get('/api/profile',visitor,(req:any,res)=>res.json(profilePayload(req.visitorId)));
app.get('/api/users/:id',(req,res)=>{const p=db.prepare("SELECT u.id,u.display_name,p.bio,p.avatar_url,u.created_at FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.id=? AND u.role='visitor'").get(req.params.id) as any;if(!p)return res.status(404).json({error:'User not found'});const activity={comments:(db.prepare("SELECT COUNT(*) n FROM comments WHERE user_id=? AND status='visible'").get(req.params.id) as any).n,reactions:(db.prepare('SELECT COUNT(*) n FROM reactions WHERE user_id=?').get(req.params.id) as any).n};res.json({...p,activity});});
app.put('/api/profile',visitor,writeLimiter,(req:any,res)=>{
  const schema=z.object({name:z.string().trim().min(1).max(60),bio:z.string().trim().max(240).default(''),avatarUrl:z.string().trim().max(500).refine(v=>!v||['http:','https:'].includes(new URL(v).protocol),'Avatar must use http/https').default('')});
  const parsed=schema.safeParse(req.body); if(!parsed.success)return res.status(400).json({error:'Profile name or bio is invalid'});
  db.prepare('UPDATE users SET display_name=? WHERE id=?').run(parsed.data.name,req.visitorId);
  db.prepare('UPDATE profiles SET bio=?,avatar_url=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(parsed.data.bio,parsed.data.avatarUrl||null,req.visitorId);
  const token=jwt.sign({role:'visitor',sub:req.visitorId,name:parsed.data.name},JWT_SECRET!,{expiresIn:'30d'});
  res.json({token,profile:profilePayload(req.visitorId)});
});

app.delete('/api/comments/:id',visitor,writeLimiter,(req:any,res)=>{
  const row=db.prepare('SELECT user_id FROM comments WHERE id=?').get(Number(req.params.id)) as any;
  if(!row)return res.status(404).json({error:'Comment not found'});
  if(row.user_id!==req.visitorId)return res.status(403).json({error:'You can only delete your own comments'});
  const post=db.prepare('SELECT post_id FROM comments WHERE id=?').get(Number(req.params.id)) as any;
  db.prepare('DELETE FROM comments WHERE id=?').run(Number(req.params.id));
  if(post) pushRealtime('comment:deleted',{postId:post.post_id,commentId:Number(req.params.id)});
  res.status(204).end();
});
app.post('/api/reports',visitor,writeLimiter,(req:any,res)=>{
  const parsed=reportSchema.safeParse(req.body); if(!parsed.success)return res.status(400).json({error:'Invalid report details'});
  const d=parsed.data;
  if(d.contentType==='post'&&!db.prepare('SELECT id FROM posts WHERE id=?').get(Number(d.contentId)))return res.status(404).json({error:'Post not found'});
  if(d.contentType==='comment'&&!db.prepare('SELECT id FROM comments WHERE id=?').get(Number(d.contentId)))return res.status(404).json({error:'Comment not found'});
  if(d.contentType==='user'&&!db.prepare('SELECT id FROM users WHERE id=?').get(d.contentId))return res.status(404).json({error:'User not found'});
  const r=db.prepare('INSERT INTO reports(reporter_user_id,content_type,content_id,reason,details) VALUES(?,?,?,?,?)').run(req.visitorId,d.contentType,d.contentId,d.reason,d.details);
  res.status(201).json({id:r.lastInsertRowid,status:'open'});
});
app.get('/api/admin/reports',adminAuth,(req,res)=>res.json(db.prepare('SELECT r.*,u.display_name reporter_name FROM reports r JOIN users u ON u.id=r.reporter_user_id ORDER BY r.id DESC LIMIT 300').all()));
app.patch('/api/admin/reports/:id',adminAuth,(req,res)=>{const parsed=z.object({status:z.enum(['open','reviewing','resolved','dismissed'])}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid report status'});const r=db.prepare('UPDATE reports SET status=? WHERE id=?').run(parsed.data.status,Number(req.params.id));res.json({updated:r.changes>0});});

app.get('/api/announcements',(req,res)=>res.json(db.prepare('SELECT id,title,body,created_at FROM announcements WHERE active=1 ORDER BY id DESC LIMIT 10').all()));
app.post('/api/admin/announcements',adminAuth,writeLimiter,(req,res)=>{const parsed=z.object({title:z.string().trim().min(1).max(140),body:z.string().trim().min(1).max(2000)}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid announcement'});const r=db.prepare('INSERT INTO announcements(admin_username,title,body) VALUES(?,?,?)').run(req.admin.sub,parsed.data.title,parsed.data.body);const users=db.prepare("SELECT id FROM users WHERE role='visitor'").all() as any[];const stmt=db.prepare('INSERT INTO notifications(type,target_user_id,payload) VALUES(?,?,?)');const tx=db.transaction(()=>users.forEach(u=>stmt.run('announcement',u.id,JSON.stringify({announcementId:Number(r.lastInsertRowid),title:parsed.data.title}))));tx();res.status(201).json(db.prepare('SELECT id,title,body,created_at FROM announcements WHERE id=?').get(r.lastInsertRowid));});
app.get('/api/admin/announcements',adminAuth,(req,res)=>res.json(db.prepare('SELECT id,title,body,active,created_at FROM announcements ORDER BY id DESC LIMIT 100').all()));
app.patch('/api/admin/announcements/:id',adminAuth,writeLimiter,(req,res)=>{const s=z.object({active:z.boolean()}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'Invalid announcement state'});const r=db.prepare('UPDATE announcements SET active=? WHERE id=?').run(s.data.active?1:0,Number(req.params.id));res.json({updated:r.changes>0});});

app.get('/api/resources',(req,res)=>res.json(db.prepare('SELECT id,title,description,url,category,created_at FROM resources ORDER BY id DESC LIMIT 100').all()));
app.post('/api/admin/resources',adminAuth,writeLimiter,(req,res)=>{const parsed=z.object({title:z.string().trim().min(1).max(140),description:z.string().trim().max(1000).default(''),url:z.string().url().max(500).refine(v=>['http:','https:'].includes(new URL(v).protocol),'Only http/https resources are allowed'),category:z.string().trim().min(1).max(60).default('general')}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid resource'});const r=db.prepare('INSERT INTO resources(admin_username,title,description,url,category) VALUES(?,?,?,?,?)').run(req.admin.sub,parsed.data.title,parsed.data.description,parsed.data.url,parsed.data.category);res.status(201).json({id:r.lastInsertRowid});});

app.get('/api/admin/comments',adminAuth,(req,res)=>res.json(db.prepare('SELECT c.*,p.title FROM comments c JOIN posts p ON p.id=c.post_id ORDER BY c.id DESC LIMIT 200').all()));
app.patch('/api/admin/comments/:id',adminAuth,(req,res)=>{const s=z.object({status:z.enum(['visible','hidden'])}).safeParse(req.body);if(!s.success)return res.status(400).json({error:'Invalid status'});const row=db.prepare('SELECT post_id FROM comments WHERE id=?').get(Number(req.params.id)) as any;const r=db.prepare('UPDATE comments SET status=? WHERE id=?').run(s.data.status,Number(req.params.id));if(r.changes&&row)pushRealtime(s.data.status==='visible'?'comment:restored':'comment:hidden',{postId:row.post_id,commentId:Number(req.params.id)});res.json({updated:r.changes>0});});

app.get('/api/conversations',visitor,(req:any,res)=>{const rows=db.prepare("SELECT c.id,c.kind,c.title,c.created_at FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id WHERE cm.user_id=? OR c.kind='community' ORDER BY c.created_at DESC").all(req.visitorId);res.json(rows);});
app.get('/api/messages',visitor,(req:any,res)=>res.json(db.prepare("SELECT id,name,body,created_at FROM messages WHERE conversation_id='community' ORDER BY id DESC LIMIT 100").all().reverse()));
app.post('/api/messages',visitor,writeLimiter,(req:any,res)=>{
  const s=messageSchema.safeParse(req.body);
  if(!s.success)return res.status(400).json({error:'Invalid message'});
  const r=db.prepare("INSERT INTO messages(conversation_id,user_id,name,body) VALUES('community',?,?,?)").run(req.visitorId,req.visitorName,s.data.body);
  const message=db.prepare('SELECT id,name,body,created_at FROM messages WHERE id=?').get(Number(r.lastInsertRowid));
  notifyUsersExcept(req.visitorId,'message',{conversationId:'community',sender:req.visitorName},Number(r.lastInsertRowid));
  pushRealtime('message:new',{conversationId:'community',message});
  res.status(201).json({id:r.lastInsertRowid,message});
});
app.post('/api/conversations/direct',visitor,writeLimiter,(req:any,res)=>{const s=z.object({userId:z.string().min(1).max(80)}).safeParse(req.body);if(!s.success||s.data.userId===req.visitorId)return res.status(400).json({error:'Invalid conversation target'});if(!db.prepare("SELECT id FROM users WHERE id=? AND role='visitor'").get(s.data.userId))return res.status(404).json({error:'User not found'});const existing=db.prepare("SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=? WHERE c.kind='direct' LIMIT 1").get(req.visitorId,s.data.userId) as any;if(existing)return res.json({id:existing.id});const id=crypto.randomUUID();db.prepare("INSERT INTO conversations(id,kind,title) VALUES(?, 'direct', NULL)").run(id);db.prepare('INSERT INTO conversation_members(conversation_id,user_id) VALUES(?,?),(?,?)').run(id,req.visitorId,id,s.data.userId);res.status(201).json({id});});
app.get('/api/conversations/:id/messages',visitor,(req:any,res)=>{const id=req.params.id;if(id!=='community'&&!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.visitorId))return res.status(403).json({error:'Not authorized for this conversation'});res.json(db.prepare('SELECT id,name,body,created_at FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT 200').all(id));});
app.post('/api/conversations/:id/messages',visitor,writeLimiter,(req:any,res)=>{
  const id=req.params.id;
  if(id!=='community'&&!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,req.visitorId))return res.status(403).json({error:'Not authorized for this conversation'});
  const s=messageSchema.safeParse(req.body);
  if(!s.success)return res.status(400).json({error:'Invalid message'});
  const r=db.prepare('INSERT INTO messages(conversation_id,user_id,name,body) VALUES(?,?,?,?)').run(id,req.visitorId,req.visitorName,s.data.body);
  const message=db.prepare('SELECT id,name,body,created_at FROM messages WHERE id=?').get(Number(r.lastInsertRowid));
  notifyConversationMembers(id,req.visitorId,'message',{conversationId:id,sender:req.visitorName},Number(r.lastInsertRowid));
  pushRealtime('message:new',{conversationId:id,message},c=>c.visitorId===req.visitorId || !!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(id,c.visitorId));
  res.status(201).json({id:r.lastInsertRowid,message});
});

app.get('/api/admin/messages',adminAuth,(req,res)=>res.json(db.prepare("SELECT id,name,body,created_at FROM messages WHERE conversation_id='community' ORDER BY id DESC LIMIT 200").all().reverse()));
app.delete('/api/admin/messages/:id',adminAuth,writeLimiter,(req,res)=>{
  const id=Number(req.params.id);
  const row=db.prepare("SELECT id,conversation_id FROM messages WHERE id=? AND conversation_id='community'").get(id) as any;
  if(!row)return res.status(404).json({error:'Community message not found'});
  db.prepare('DELETE FROM messages WHERE id=?').run(id);
  pushRealtime('message:deleted',{conversationId:'community',messageId:id});
  res.status(204).end();
});

app.get('/api/admin/notifications',adminAuth,(req,res)=>res.json(db.prepare('SELECT id,type,payload,read_at,created_at FROM notifications WHERE target_admin_username=? ORDER BY id DESC LIMIT 100').all(req.admin.sub)));
app.patch('/api/admin/notifications/:id/read',adminAuth,(req,res)=>{const r=db.prepare('UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE id=? AND target_admin_username=?').run(Number(req.params.id),req.admin.sub);res.json({updated:r.changes>0});});
app.get('/api/notifications',visitor,(req:any,res)=>res.json(db.prepare('SELECT id,type,payload,read_at,created_at FROM notifications WHERE target_user_id=? ORDER BY id DESC LIMIT 50').all(req.visitorId)));
app.patch('/api/notifications/:id/read',visitor,(req:any,res)=>{const r=db.prepare('UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE id=? AND target_user_id=?').run(Number(req.params.id),req.visitorId);res.json({updated:r.changes>0});});
app.get('/api/health',(req,res)=>res.json({ok:true,service:'IR EN DARK'}));

app.use((err:any,_req:any,res:any,_next:any)=>{if(err?.code==='LIMIT_FILE_SIZE')return res.status(413).json({error:'Uploaded media is too large'});if(err?.name==='MulterError')return res.status(400).json({error:'Invalid media upload'});console.error(err);res.status(500).json({error:'Internal server error'});});

const clientDist=path.join(__dirname,'../dist');
if(fs.existsSync(clientDist)){app.use(express.static(clientDist));app.use((req,res)=>res.sendFile(path.join(clientDist,'index.html')));}
const port=Number(process.env.PORT||3000);
app.listen(port,'0.0.0.0',()=>console.log(`IR EN DARK server listening on ${port}`));
