// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
const { exec } = require('child_process');
const fs = require('fs'); 
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs'); 
const PgStore = require('connect-pg-simple')(session); 
const { createWorker } = require('tesseract.js');
const https = require('https');
const archiver = require('archiver');
const { parse } = require('csv-parse/sync');
const { Parser } = require('json2csv');
const cors = require('cors'); 

const app = express();
const port = process.env.PORT || 3000;

// ★★★ Render設定 & CORS許可 ★★★
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));

// --- 1. データベース接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 4, 
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});
pool.on('error', (err) => console.error('DB Error:', err));

// --- 2. ストレージ設定 ---
const s3Client = new S3Client({ 
    region: 'auto', 
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`, 
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } 
});

const upload = multer({ 
    storage: multer.memoryStorage(), 
    limits: { fileSize: 500 * 1024 * 1024 }, 
    fileFilter: (req, f, cb) => { 
        if(f.mimetype.startsWith('image/') || f.mimetype.startsWith('video/') || f.mimetype==='application/pdf'|| f.mimetype.includes('csv') || f.originalname.toLowerCase().endsWith('.csv')) {
            cb(null, true);
        } else {
            cb(new Error('許可されていないファイル形式です'), false);
        }
    } 
});

const tempUpload = multer({ dest: 'temp_uploads/' });
if (!fs.existsSync('temp_uploads')) fs.mkdirSync('temp_uploads');

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- ▼ 認証設定 ▼ ---
app.use(session({
    store: new PgStore({ pool: pool, tableName: 'user_sessions', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'secret_key', 
    resave: false, 
    saveUninitialized: false, 
    proxy: true,
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, 
        secure: true,        // Render(HTTPS)用
        httpOnly: true, 
        sameSite: 'none'     // クロスオリジン用
    } 
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (rows.length === 0) return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
        const user = rows[0];
        if (await bcrypt.compare(password, user.password_hash)) return done(null, user);
        else return done(null, false, { message: 'ユーザー名またはパスワードが違います。' });
    } catch (error) { return done(error); }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (rows.length > 0) done(null, rows[0]); else done(new Error('User not found'));
    } catch (error) { done(error); }
});
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: 'ログインが必要です。' });
}
const apiHandler = (fn) => async (req, res, next) => { try { await fn(req, res, next); } catch (e) { next(e); } };

// --- DB初期化 ---
const createTable = async () => {
    try {
        const client = await pool.connect();
        try {
            await client.query(`CREATE TABLE IF NOT EXISTS images (id SERIAL PRIMARY KEY, title VARCHAR(1024) NOT NULL, url VARCHAR(1024) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
            await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
            await client.query(`CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default" PRIMARY KEY, "sess" json NOT NULL, "expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE);`);
            await client.query(`CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");`);
            await client.query(`CREATE TABLE IF NOT EXISTS product_info (product_code VARCHAR(255) PRIMARY KEY, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
            await client.query(`CREATE TABLE IF NOT EXISTS csv_uploads (id SERIAL PRIMARY KEY, filename VARCHAR(255) NOT NULL, uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
            const addCol = async (table, col, type) => { await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='${table}' AND column_name='${col}') THEN ALTER TABLE ${table} ADD COLUMN ${col} ${type}; END IF; END $$;`); };
            await addCol('images', 'category_1', 'VARCHAR(100) DEFAULT \'default_cat1\'');
            await addCol('images', 'category_2', 'VARCHAR(100) DEFAULT \'default_cat2\'');
            await addCol('images', 'category_3', 'VARCHAR(100) DEFAULT \'default_cat3\'');
            await addCol('images', 'folder_name', 'VARCHAR(100) DEFAULT \'default_folder\'');
            await addCol('product_info', 'product_name', 'VARCHAR(1024)');
            await addCol('product_info', 'model_num1', 'VARCHAR(255)');
            await addCol('product_info', 'model_num2', 'VARCHAR(255)');
            await addCol('product_info', 'model_num3', 'VARCHAR(255)');
            await addCol('product_info', 'model_num4', 'VARCHAR(255)');
            await addCol('product_info', 'condition', 'VARCHAR(255)');
            await addCol('product_info', 'series', 'VARCHAR(255)');
            await addCol('product_info', 'stock', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'ec_price', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'mercari_price', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'image_filename', 'VARCHAR(1024)');
            await addCol('product_info', 'csv_upload_id', 'INTEGER');
            await client.query(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='product_info' AND column_name='code') THEN ALTER TABLE product_info RENAME COLUMN code TO product_code; END IF; END $$;`);
            await addCol('csv_uploads', 'category_1', 'VARCHAR(100) DEFAULT \'未分類\'');
            await addCol('csv_uploads', 'category_2', 'VARCHAR(100) DEFAULT \'-\'');
            await addCol('csv_uploads', 'category_3', 'VARCHAR(100) DEFAULT \'-\'');
            try { await client.query('CREATE EXTENSION IF NOT EXISTS pg_trgm;'); await client.query('CREATE INDEX IF NOT EXISTS idx_images_title_trgm ON images USING gin (title gin_trgm_ops);'); await client.query('CREATE INDEX IF NOT EXISTS idx_product_info_name_trgm ON product_info USING gin (product_name gin_trgm_ops);'); await client.query('CREATE INDEX IF NOT EXISTS idx_product_info_model_trgm ON product_info USING gin (model_num1 gin_trgm_ops);'); } catch (e) {}
        } finally { client.release(); }
    } catch (err) { console.error('DB Init Error:', err); }
};

// --- ルート設定 ---
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/personal', (req, res) => res.sendFile(path.join(__dirname, 'personal.html')));
app.get('/product-manager', (req, res) => res.sendFile(path.join(__dirname, 'product_manager.html')));
app.get('/pdf-tool', (req, res) => res.sendFile(path.join(__dirname, 'pdf_tool.html')));

// API群
app.post('/api/auth/register', async (req, res) => { const { username, password } = req.body; if (!username || !password || password.length < 8) return res.status(400).json({ message: 'ユーザー名と8文字以上のパスワード必須' }); try { const hash = await bcrypt.hash(password, 10); await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]); res.status(201).json({ message: '登録成功' }); } catch (e) { if (e.code === '23505') res.status(409).json({ message: 'そのユーザー名は使用済みです' }); else res.status(500).json({ message: 'サーバーエラー' }); } });
app.post('/api/auth/login', (req, res, next) => { passport.authenticate('local', (err, user, info) => { if (err) return next(err); if (!user) return res.status(401).json({ message: info.message || 'ログイン失敗' }); req.logIn(user, (err) => { if (err) return next(err); return res.json({ message: 'ログイン成功', user: user.username }); }); })(req, res, next); });
app.post('/api/auth/logout', (req, res, next) => { req.logout((err) => { if(err)return next(err); req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({message:'ログアウト'}); }); }); });
app.get('/api/auth/check', (req, res) => { if (req.isAuthenticated()) res.json({ loggedIn: true, username: req.user.username }); else res.json({ loggedIn: false }); });
app.post('/api/admin/init-db', isAuthenticated, apiHandler(async (req, res) => { await createTable(); res.json({ message: 'データベース構成を更新しました。' }); }));

// ★★★ 修正版: 検索API (ページネーション対応) ★★★
app.get('/api/search', isAuthenticated, apiHandler(async (req, res) => {
    const { cat1, cat2, cat3, folder, q, sort, order, limit, offset } = req.query;

    const s = sort === 'title' ? 'i.title' : 'i.created_at'; 
    const d = order === 'ASC' ? 'ASC' : 'DESC';
    // デフォルト: 100件ずつ, オフセット0
    const l = parseInt(limit) || 100;
    const o = parseInt(offset) || 0;

    let sql = `SELECT i.*, p.product_name, p.model_num1, p.model_num2, p.model_num3, p.model_num4, p.ec_price, p.mercari_price, p.stock FROM images i LEFT JOIN product_info p ON (p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename)) WHERE 1=1`;
    let params = []; let pIdx = 1;
    
    if (cat1) { sql += ` AND i.category_1=$${pIdx++}`; params.push(cat1); }
    if (cat2) { sql += ` AND i.category_2=$${pIdx++}`; params.push(cat2); }
    if (cat3) { sql += ` AND i.category_3=$${pIdx++}`; params.push(cat3); }
    if (folder) { sql += ` AND i.folder_name=$${pIdx++}`; params.push(folder); }
    if (q) { 
        const keywords = q.replace(/　/g, ' ').trim().split(/\s+/); 
        keywords.forEach(word => { 
            if(word) {
                sql += ` AND (i.title ILIKE $${pIdx} OR p.product_name ILIKE $${pIdx} OR p.model_num1 ILIKE $${pIdx} OR p.model_num2 ILIKE $${pIdx} OR p.model_num3 ILIKE $${pIdx} OR p.model_num4 ILIKE $${pIdx} OR p.product_code ILIKE $${pIdx})`; 
                params.push(`%${word}%`); pIdx++;
            }
        }); 
    }
    
    // LIMIT / OFFSET を適用
    sql += ` ORDER BY ${s} ${d} LIMIT $${pIdx++} OFFSET $${pIdx++}`; 
    params.push(l, o);

    const { rows } = await pool.query(sql, params); 
    res.json(rows);
}));

app.post('/upload', isAuthenticated, (req, res, next) => { upload.array('imageFiles', 100)(req, res, (err) => { if (err) return next(err); next(); }); }, apiHandler(async (req, res) => { const { category1, category2, category3, folderName } = req.body; if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'No files' }); const c1 = category1.trim(); const c2 = category2.trim(); const c3 = category3.trim(); const f = folderName.trim(); const values = [], params = []; let idx = 1; for (const file of req.files) { const name = Buffer.from(file.originalname, 'latin1').toString('utf8'); const key = `${c1}/${c2}/${c3}/${f}/${name}`; await s3Client.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: file.buffer, ContentType: file.mimetype })); const url = `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(key)}`; values.push(`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`); params.push(key, url, c1, c2, c3, f); } await pool.query(`INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) VALUES ${values.join(', ')}`, params); res.json({ message: `${req.files.length}件 保存完了` }); }));
app.post('/api/products/export-csv', isAuthenticated, apiHandler(async (req, res) => { const { targetIds } = req.body; let sql = `SELECT i.*, p.product_name, p.model_num1, p.model_num2, p.model_num3, p.model_num4, p.ec_price, p.mercari_price, p.stock FROM images i LEFT JOIN product_info p ON (p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename))`; let params = []; if (targetIds && Array.isArray(targetIds) && targetIds.length > 0) { sql += ` WHERE i.id = ANY($1::int[])`; params.push(targetIds); } else { return res.status(400).send('対象が選択されていません'); } sql += ` ORDER BY i.created_at DESC`; const { rows } = await pool.query(sql, params); if (rows.length === 0) return res.status(404).send('データが見つかりません'); const csvData = rows.map(item => ({ '画像URL': item.url || '', 'ファイル名': item.title ? item.title.split('/').pop() : '', '商品名': item.product_name || '', '型番': [item.model_num1, item.model_num2].filter(Boolean).join(' '), '在庫': item.stock || 0, 'EC価格': item.ec_price || 0, 'メルカリ価格': item.mercari_price || 0, '登録日': item.created_at ? new Date(item.created_at).toLocaleDateString('ja-JP') : '' })); const json2csvParser = new Parser({ withBOM: true }); const csv = json2csvParser.parse(csvData); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="selected_products.csv"'); res.status(200).send(csv); }));
// その他API群 (省略せず記述)
const getCategoryList = (col, level) => apiHandler(async (req, res) => { let query = "", params = []; let countQuery = "", countParams = []; if (level === 1) { query = `SELECT ${col} FROM images UNION SELECT ${col} FROM csv_uploads ORDER BY ${col}`; countQuery = `SELECT ${col} as name, COUNT(*) as cnt FROM images GROUP BY ${col}`; } else if (level === 2) { query = `SELECT ${col} FROM images WHERE category_1=$1 UNION SELECT ${col} FROM csv_uploads WHERE category_1=$2 ORDER BY ${col}`; params = [req.params.c1, req.params.c1]; countQuery = `SELECT ${col} as name, COUNT(*) as cnt FROM images WHERE category_1=$1 GROUP BY ${col}`; countParams = [req.params.c1]; } else { query = `SELECT ${col} FROM images WHERE category_1=$1 AND category_2=$2 UNION SELECT ${col} FROM csv_uploads WHERE category_1=$3 AND category_2=$4 ORDER BY ${col}`; params = [req.params.c1, req.params.c2, req.params.c1, req.params.c2]; countQuery = `SELECT ${col} as name, COUNT(*) as cnt FROM images WHERE category_1=$1 AND category_2=$2 GROUP BY ${col}`; countParams = [req.params.c1, req.params.c2]; } const { rows: nameRows } = await pool.query(query, params); const distinctNames = [...new Set(nameRows.map(r => r[col]))].filter(v => v); const { rows: countRows } = await pool.query(countQuery, countParams); const countMap = {}; countRows.forEach(r => countMap[r.name] = parseInt(r.cnt)); const result = distinctNames.map(name => ({ name: name, count: countMap[name] || 0 })); res.json(result); });
app.get('/api/cat1', isAuthenticated, getCategoryList('category_1', 1));
app.get('/api/cat2/:c1', isAuthenticated, getCategoryList('category_2', 2));
app.get('/api/cat3/:c1/:c2', isAuthenticated, getCategoryList('category_3', 3));
app.get('/api/folders/:c1/:c2/:c3', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query(`SELECT folder_name as name, COUNT(*) as count FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 GROUP BY folder_name ORDER BY folder_name`, [req.params.c1, req.params.c2, req.params.c3]); res.json(rows.map(r => ({ name: r.name, count: parseInt(r.count) }))); }));
app.get('/api/products/stats', isAuthenticated, apiHandler(async (req, res) => { const imgCount = (await pool.query('SELECT COUNT(*) FROM images')).rows[0].count; const prodCount = (await pool.query('SELECT COUNT(*) FROM product_info')).rows[0].count; const linkedCount = (await pool.query(`SELECT COUNT(DISTINCT i.id) FROM images i JOIN product_info p ON (p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename))`)).rows[0].count; res.json({ images: imgCount, products: prodCount, linked: linkedCount }); }));
app.get('/api/products/all', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT * FROM product_info ORDER BY updated_at DESC LIMIT 500'); res.json(rows); }));
app.get('/api/debug/mismatch', isAuthenticated, apiHandler(async (req, res) => { try { const prodRows = await pool.query(`SELECT product_name, image_filename, product_code, model_num1 FROM product_info p WHERE p.image_filename IS NOT NULL AND p.image_filename <> '' AND NOT EXISTS (SELECT 1 FROM images i WHERE i.title LIKE '%' || p.image_filename) LIMIT 5`); const imgRows = await pool.query(`SELECT title FROM images i WHERE NOT EXISTS (SELECT 1 FROM product_info p WHERE p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || p.image_filename) ORDER BY created_at DESC LIMIT 5`); res.json({ unlinkedProducts: prodRows.rows, unlinkedImages: imgRows.rows }); } catch(e) { res.status(500).json({message: 'Error: ' + e.message}); } }));
app.get('/api/products/template', isAuthenticated, (req, res) => { const header = "商品名,型番1,型番2,型番3,型番4,状態,カードのシリーズ,在庫,ECサイト価格,メルカリ価格,商品コード,商品画像名\n"; const example = "テストカード,DM-01,,,A,基本セット,10,100,300,CODE001,DM-01.jpg\n"; res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="template.csv"'); res.send('\uFEFF' + header + example); });
app.post('/api/products/import', isAuthenticated, (req, res, next) => { upload.single('csvFile')(req, res, (err) => { if (err) return next(err); next(); }); }, apiHandler(async (req, res) => { if (!req.file) return res.status(400).json({ message: 'CSVファイルがありません' }); const { category1, category2, category3 } = req.body; const c1 = category1 || '未分類'; const c2 = category2 || '-'; const c3 = category3 || '-'; const csvData = req.file.buffer.toString('utf-8').replace(/^\uFEFF/, ''); const records = parse(csvData, { columns: ['product_name','model_num1','model_num2','model_num3','model_num4','condition','series','stock','ec_price','mercari_price','product_code','image_filename'], from_line: 2, skip_empty_lines: true, trim: true }); const client = await pool.connect(); try { await client.query('BEGIN'); const fileRes = await client.query('INSERT INTO csv_uploads (filename, category_1, category_2, category_3) VALUES ($1, $2, $3, $4) RETURNING id', [req.file.originalname, c1, c2, c3]); const uploadId = fileRes.rows[0].id; for (const row of records) { if (!row.product_code) continue; const query = `INSERT INTO product_info (product_name, model_num1, model_num2, model_num3, model_num4, condition, series, stock, ec_price, mercari_price, product_code, image_filename, csv_upload_id, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP) ON CONFLICT (product_code) DO UPDATE SET product_name=EXCLUDED.product_name, model_num1=EXCLUDED.model_num1, model_num2=EXCLUDED.model_num2, model_num3=EXCLUDED.model_num3, model_num4=EXCLUDED.model_num4, condition=EXCLUDED.condition, series=EXCLUDED.series, stock=EXCLUDED.stock, ec_price=EXCLUDED.ec_price, mercari_price=EXCLUDED.mercari_price, image_filename=EXCLUDED.image_filename, csv_upload_id=EXCLUDED.csv_upload_id, updated_at=CURRENT_TIMESTAMP`; const stock = parseInt(row.stock || '0'); const ec = parseInt(row.ec_price || '0'); const mer = parseInt(row.mercari_price || '0'); await client.query(query, [row.product_name, row.model_num1, row.model_num2 || null, row.model_num3 || null, row.model_num4 || null, row.condition, row.series, stock, ec, mer, row.product_code, row.image_filename, uploadId]); } await client.query('COMMIT'); res.json({ message: `${req.file.originalname} を登録しました (${records.length}件)` }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.get('/api/products/files', isAuthenticated, apiHandler(async (req, res) => { try { const { rows } = await pool.query("SELECT * FROM csv_uploads WHERE filename <> '__CATEGORY_NODE__' ORDER BY uploaded_at DESC"); res.json(rows); } catch (e) { res.json([]); } }));
app.post('/api/categories/create', isAuthenticated, apiHandler(async (req, res) => { const { category1, category2, category3 } = req.body; if (!category1) return res.status(400).json({ message: '大カテゴリは必須です' }); const client = await pool.connect(); try { await client.query('BEGIN'); const check = await client.query("SELECT id FROM csv_uploads WHERE filename = '__CATEGORY_NODE__' AND category_1=$1 AND category_2=$2 AND category_3=$3", [category1, category2 || '-', category3 || '-']); if (check.rows.length === 0) { await client.query("INSERT INTO csv_uploads (filename, category_1, category_2, category_3) VALUES ($1, $2, $3, $4)", ['__CATEGORY_NODE__', category1, category2 || '-', category3 || '-']); } await client.query('COMMIT'); res.json({ message: 'カテゴリを作成しました' }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.put('/api/products/files/:id', isAuthenticated, apiHandler(async (req, res) => { const { filename, category1, category2, category3 } = req.body; await pool.query('UPDATE csv_uploads SET filename = $1, category_1 = $2, category_2 = $3, category_3 = $4 WHERE id = $5', [filename, category1, category2, category3, req.params.id]); res.json({ message: '変更しました' }); }));
app.delete('/api/products/files/:id', isAuthenticated, apiHandler(async (req, res) => { const client = await pool.connect(); try { await client.query('BEGIN'); await client.query('DELETE FROM product_info WHERE csv_upload_id = $1', [req.params.id]); await client.query('DELETE FROM csv_uploads WHERE id = $1', [req.params.id]); await client.query('COMMIT'); res.json({ message: '削除しました' }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.get('/api/products/files/:id/download', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query(`SELECT product_name, model_num1, model_num2, model_num3, model_num4, condition, series, stock, ec_price, mercari_price, product_code, image_filename FROM product_info WHERE csv_upload_id = $1 ORDER BY product_code`, [req.params.id]); if (rows.length === 0) return res.status(404).send('Data not found'); let csv = "商品名,型番1,型番2,型番3,型番4,状態,カードのシリーズ,在庫,ECサイト価格,メルカリ価格,商品コード,商品画像名\n"; rows.forEach(r => { csv += `"${r.product_name}","${r.model_num1}","${r.model_num2||''}","${r.model_num3||''}","${r.model_num4||''}","${r.condition}","${r.series}",${r.stock},${r.ec_price},${r.mercari_price},"${r.product_code}","${r.image_filename}"\n`; }); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename="backup_${req.params.id}.csv"`); res.status(200).send('\uFEFF' + csv); }));
app.put('/api/image/:title', isAuthenticated, apiHandler(async (req, res) => { const { title } = req.params; const { category1, category2, category3, folderName } = req.body; const name = title.split('/').pop(); const newKey = `${category1}/${category2}/${category3}/${folderName}/${name}`; await s3Client.send(new CopyObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, CopySource: `${process.env.R2_BUCKET_NAME}/${title}`, Key: newKey })); await s3Client.send(new S3DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: title })); await pool.query(`UPDATE images SET category_1=$1, category_2=$2, category_3=$3, folder_name=$4, title=$5, url=$6 WHERE title=$7`, [category1, category2, category3, folderName, newKey, `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(newKey)}`, title]); res.json({ message: "移動完了" }); }));
app.delete('/api/folder/:name', isAuthenticated, apiHandler(async(req,res) => {const {rows}=await pool.query(`SELECT title FROM images WHERE folder_name=$1`,[req.params.name]); if(rows.length>0){ const keys=rows.map(r=>({Key:r.title})); for(let i=0;i<keys.length;i+=1000)await s3Client.send(new DeleteObjectsCommand({Bucket:process.env.R2_BUCKET_NAME,Delete:{Objects:keys.slice(i,i+1000)}})); } await pool.query(`DELETE FROM images WHERE folder_name=$1`,[req.params.name]); res.json({message:"削除完了"}); }));
const updateCategoryName = async (level, oldName, newName, parent1, parent2) => { const client = await pool.connect(); try { await client.query('BEGIN'); if (level === 1) { await client.query('UPDATE images SET category_1=$1 WHERE category_1=$2', [newName, oldName]); await client.query('UPDATE csv_uploads SET category_1=$1 WHERE category_1=$2', [newName, oldName]); } else if (level === 2) { await client.query('UPDATE images SET category_2=$1 WHERE category_1=$2 AND category_2=$3', [newName, parent1, oldName]); await client.query('UPDATE csv_uploads SET category_2=$1 WHERE category_1=$2 AND category_2=$3', [newName, parent1, oldName]); } else if (level === 3) { await client.query('UPDATE images SET category_3=$1 WHERE category_1=$2 AND category_2=$3 AND category_3=$4', [newName, parent1, parent2, oldName]); await client.query('UPDATE csv_uploads SET category_3=$1 WHERE category_1=$2 AND category_2=$3 AND category_3=$4', [newName, parent1, parent2, oldName]); } await client.query('COMMIT'); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } };
app.put('/api/cat1/:old', isAuthenticated, apiHandler(async(req, res) => { await updateCategoryName(1, req.params.old, req.body.newName); res.json({message:'OK'}); }));
app.put('/api/cat2/:c1/:old', isAuthenticated, apiHandler(async(req, res) => { await updateCategoryName(2, req.params.old, req.body.newName, req.params.c1); res.json({message:'OK'}); }));
app.put('/api/cat3/:c1/:c2/:old', isAuthenticated, apiHandler(async(req, res) => { await updateCategoryName(3, req.params.old, req.body.newName, req.params.c1, req.params.c2); res.json({message:'OK'}); }));
app.put('/api/folder/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET folder_name=$1 WHERE folder_name=$2', [req.body.newName, req.params.old]); res.json({message:'OK'}); }));
app.delete('/api/cat1/:name', isAuthenticated, apiHandler(async(req, res) => { const client = await pool.connect(); try { await client.query('BEGIN'); await client.query(`DELETE FROM images WHERE category_1=$1`, [req.params.name]); await client.query(`DELETE FROM csv_uploads WHERE category_1=$1`, [req.params.name]); await client.query('COMMIT'); res.json({message:'OK'}); } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.delete('/api/cat2/:c1/:name', isAuthenticated, apiHandler(async(req, res) => { const client = await pool.connect(); try { await client.query('BEGIN'); await client.query(`DELETE FROM images WHERE category_1=$1 AND category_2=$2`, [req.params.c1, req.params.name]); await client.query(`DELETE FROM csv_uploads WHERE category_1=$1 AND category_2=$2`, [req.params.c1, req.params.name]); await client.query('COMMIT'); res.json({message:'OK'}); } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.delete('/api/cat3/:c1/:c2/:name', isAuthenticated, apiHandler(async(req, res) => { const client = await pool.connect(); try { await client.query('BEGIN'); await client.query(`DELETE FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3`, [req.params.c1, req.params.c2, req.params.name]); await client.query(`DELETE FROM csv_uploads WHERE category_1=$1 AND category_2=$2 AND category_3=$3`, [req.params.c1, req.params.c2, req.params.name]); await client.query('COMMIT'); res.json({message:'OK'}); } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.delete('/api/personal/album/:name', isAuthenticated, apiHandler(async (req, res) => { await performDelete(res, "category_1='Private' AND folder_name=$1", [req.params.name]); }));
app.get('/api/personal/download/:folder', isAuthenticated, apiHandler(async (req, res) => { const folder = req.params.folder; const { rows } = await pool.query(`SELECT title FROM images WHERE category_1='Private' AND folder_name=$1`, [folder]); if (rows.length === 0) return res.status(404).send('Empty'); res.attachment(`${encodeURIComponent(folder)}.zip`); const archive = archiver('zip', { zlib: { level: 9 } }); archive.pipe(res); for (const row of rows) { try { const s3Item = await s3Client.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: row.title })); archive.append(s3Item.Body, { name: row.title.split('/').pop() }); } catch (e) {} } await archive.finalize(); }));
app.post('/api/pdf/convert', isAuthenticated, tempUpload.single('pdfFile'), (req, res) => { if (!req.file) return res.status(400).json({ message: 'ファイルがありません' }); const targetFormat = req.body.format || 'docx'; if (!['docx', 'xlsx'].includes(targetFormat)) return res.status(400).json({ message: '無効な形式です' }); const inputPath = req.file.path; const outputExtension = '.' + targetFormat; const outputFilename = req.file.originalname.replace(/\.pdf$/i, '') + outputExtension; const outputPath = inputPath + outputExtension; const executePython = (cmd3, cmd2, callback) => { exec(cmd3, (err3, stdout3, stderr3) => { if (!err3) return callback(null, stdout3); exec(cmd2, (err2, stdout2, stderr2) => { if (!err2) return callback(null, stdout2); callback(err3 || err2, null); }); }); }; const cmdArgs = `converter.py "${inputPath}" "${outputPath}" "${targetFormat}"`; executePython(`python3 ${cmdArgs}`, `python ${cmdArgs}`, (error, stdout) => { if (error) { console.error('Conversion Error:', error); fs.unlink(inputPath, ()=>{}); return res.status(500).json({ message: '変換失敗' }); } res.download(outputPath, outputFilename, (err) => { fs.unlink(inputPath, ()=>{}); fs.unlink(outputPath, ()=>{}); }); }); });

app.use((err, req, res, next) => { console.error("Global Error Handler:", err); res.status(500).json({ message: "システムエラー: " + (err.message || "Unknown error detected") }); });
app.listen(port, async () => { await createTable(); console.log(`Server running on ${port}`); });