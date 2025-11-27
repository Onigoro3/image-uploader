// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');

const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs'); 
const PgStore = require('connect-pg-simple')(session); 

const { createWorker } = require('tesseract.js');
const https = require('https');
const archiver = require('archiver');
const { parse } = require('csv-parse/sync');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const port = process.env.PORT || 3000;

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
    fileFilter: (req, f, cb) => { 
        if(f.mimetype.startsWith('image/') || f.mimetype==='application/pdf'|| f.mimetype.includes('csv') || f.originalname.endsWith('.csv')) {
            cb(null, true);
        } else {
            cb(null, false);
        }
    } 
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- ▼ 認証設定 ▼ ---
app.use(session({
    store: new PgStore({ pool: pool, tableName: 'user_sessions', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'secret_key', 
    resave: false, saveUninitialized: false, proxy: true, 
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: 'auto', httpOnly: true, sameSite: 'lax' } 
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

const apiHandler = (fn) => async (req, res, next) => { 
    try { await fn(req, res, next); } 
    catch (e) { 
        console.error("API Error:", e); 
        res.status(500).json({ message: e.message || "Error" }); 
    } 
};

// --- DB初期化 (自動修復付き) ---
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

            const addCol = async (table, col, type) => {
                await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='${table}' AND column_name='${col}') THEN ALTER TABLE ${table} ADD COLUMN ${col} ${type}; END IF; END $$;`);
            };

            await addCol('images', 'category_1', 'VARCHAR(100) DEFAULT \'default_cat1\'');
            await addCol('images', 'category_2', 'VARCHAR(100) DEFAULT \'default_cat2\'');
            await addCol('images', 'category_3', 'VARCHAR(100) DEFAULT \'default_cat3\'');
            await addCol('images', 'folder_name', 'VARCHAR(100) DEFAULT \'default_folder\'');

            await addCol('product_info', 'product_name', 'VARCHAR(1024)');
            await addCol('product_info', 'model_num1', 'VARCHAR(255)');
            await addCol('product_info', 'model_num2', 'VARCHAR(255)');
            await addCol('product_info', 'condition', 'VARCHAR(255)');
            await addCol('product_info', 'series', 'VARCHAR(255)');
            await addCol('product_info', 'stock', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'ec_price', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'mercari_price', 'INTEGER DEFAULT 0');
            await addCol('product_info', 'image_filename', 'VARCHAR(1024)');
            await addCol('product_info', 'csv_upload_id', 'INTEGER');
            await addCol('product_info', 'mercari_product_id', 'VARCHAR(255)');

            await client.query(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='product_info' AND column_name='code') THEN ALTER TABLE product_info RENAME COLUMN code TO product_code; END IF; END $$;`);

            await addCol('csv_uploads', 'category_1', 'VARCHAR(100) DEFAULT \'未分類\'');
            await addCol('csv_uploads', 'category_2', 'VARCHAR(100) DEFAULT \'-\'');
            await addCol('csv_uploads', 'category_3', 'VARCHAR(100) DEFAULT \'-\'');

            console.log('Database schema synced.');
        } finally { client.release(); }
    } catch (err) { console.error('DB Init Error:', err); }
};

// --- ルート設定 ---
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/personal', (req, res) => res.sendFile(path.join(__dirname, 'personal.html')));
app.get('/product-manager', (req, res) => res.sendFile(path.join(__dirname, 'product_manager.html')));

// 認証API
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 8) return res.status(400).json({ message: 'ユーザー名と8文字以上のパスワード必須' });
    try { const hash = await bcrypt.hash(password, 10); await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]); res.status(201).json({ message: '登録成功' });
    } catch (e) { if (e.code === '23505') res.status(409).json({ message: 'そのユーザー名は使用済みです' }); else res.status(500).json({ message: 'サーバーエラー' }); }
});
app.post('/api/auth/login', (req, res, next) => { passport.authenticate('local', (err, user, info) => { if (err) return next(err); if (!user) return res.status(401).json({ message: info.message || 'ログイン失敗' }); req.logIn(user, (err) => { if (err) return next(err); return res.json({ message: 'ログイン成功', user: user.username }); }); })(req, res, next); });
app.post('/api/auth/logout', (req, res, next) => { req.logout((err) => { if(err)return next(err); req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({message:'ログアウト'}); }); }); });
app.get('/api/auth/check', (req, res) => { if (req.isAuthenticated()) res.json({ loggedIn: true, username: req.user.username }); else res.json({ loggedIn: false }); });

app.post('/api/admin/init-db', isAuthenticated, apiHandler(async (req, res) => { await createTable(); res.json({ message: 'データベース構成を更新しました。' }); }));

// --- カテゴリ ---
const getCategoryList = (col, level) => apiHandler(async (req, res) => {
    const type = req.query.type; let query = "", params = []; let where = "";
    if (level === 2) { where = `WHERE category_1 = $1`; params = [req.params.c1]; }
    if (level === 3) { where = `WHERE category_1 = $1 AND category_2 = $2`; params = [req.params.c1, req.params.c2]; }
    if (type === 'image') query = `SELECT DISTINCT ${col} FROM images ${where} ORDER BY ${col}`;
    else if (type === 'csv') query = `SELECT DISTINCT ${col} FROM csv_uploads ${where} ORDER BY ${col}`;
    else {
        if (level === 1) query = `SELECT ${col} FROM images UNION SELECT ${col} FROM csv_uploads ORDER BY ${col}`;
        else if (level === 2) { query = `SELECT ${col} FROM images WHERE category_1=$1 UNION SELECT ${col} FROM csv_uploads WHERE category_1=$2 ORDER BY ${col}`; params = [req.params.c1, req.params.c1]; }
        else { query = `SELECT ${col} FROM images WHERE category_1=$1 AND category_2=$2 UNION SELECT ${col} FROM csv_uploads WHERE category_1=$3 AND category_2=$4 ORDER BY ${col}`; params = [req.params.c1, req.params.c2, req.params.c1, req.params.c2]; }
    }
    const { rows } = await pool.query(query, params); res.json(rows.map(r => r[col]));
});
app.get('/api/cat1', isAuthenticated, getCategoryList('category_1', 1));
app.get('/api/cat2/:c1', isAuthenticated, getCategoryList('category_2', 2));
app.get('/api/cat3/:c1/:c2', isAuthenticated, getCategoryList('category_3', 3));
app.get('/api/folders/:c1/:c2/:c3', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT folder_name FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 ORDER BY folder_name', [req.params.c1, req.params.c2, req.params.c3]); res.json(rows.map(r => r.folder_name)); }));

// --- メルカリ連携 (自動探索) ---
app.post('/api/mercari/pull-stock', isAuthenticated, apiHandler(async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: 'アクセストークンが必要です' });

    // 接続候補 (ユーザーID入り、なし、v1、ルート)
    const ENDPOINTS = [
        'https://api.mercari-shops.com/v1/graphql',
        'https://api.mercari-shops.com/graphql',
        'https://api.mercari-shops.com/v1/shops/LZTviPdpw7sHE9dYjZZsq6/graphql' 
    ];
    const query = `query GetProducts { products(first: 50) { edges { node { id variants { id inventory { stockQuantity } } } } } }`;

    let lastError = "";
    for (const url of ENDPOINTS) {
        try {
            console.log(`Trying Mercari API: ${url}`);
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ query })
            });
            
            if (response.ok) {
                const result = await response.json();
                if (result.errors) throw new Error(JSON.stringify(result.errors));
                
                // 成功したらDB更新
                let updateCount = 0;
                const products = result.data?.products?.edges || [];
                for (const edge of products) {
                    const p = edge.node;
                    const stock = p.variants?.[0]?.inventory?.stockQuantity;
                    if (p.id && stock !== undefined) {
                        const r = await pool.query('UPDATE product_info SET stock=$1, updated_at=CURRENT_TIMESTAMP WHERE mercari_product_id=$2', [stock, p.id]);
                        if(r.rowCount>0) updateCount++;
                    }
                }
                return res.json({ message: `成功: ${updateCount}件 更新`, totalChecked: products.length });
            }
            lastError = `Status ${response.status}`;
        } catch (e) { lastError = e.message; }
    }
    res.status(500).json({ message: '全ての接続先で失敗', details: lastError });
}));

// --- 商品管理 ---
app.get('/api/products/stats', isAuthenticated, apiHandler(async (req, res) => {
    const imgCount = (await pool.query('SELECT COUNT(*) FROM images')).rows[0].count;
    const prodCount = (await pool.query('SELECT COUNT(*) FROM product_info')).rows[0].count;
    const linkedCount = (await pool.query(`SELECT COUNT(DISTINCT i.id) FROM images i JOIN product_info p ON ((p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename)) OR (p.product_code IS NOT NULL AND p.product_code <> '' AND i.title LIKE '%' || TRIM(p.product_code) || '%') OR (p.model_num1 IS NOT NULL AND p.model_num1 <> '' AND i.title LIKE '%' || TRIM(p.model_num1) || '%'))`)).rows[0].count;
    res.json({ images: imgCount, products: prodCount, linked: linkedCount });
}));
app.get('/api/products/all', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT * FROM product_info ORDER BY updated_at DESC LIMIT 500'); res.json(rows); }));

app.get('/api/debug/mismatch', isAuthenticated, apiHandler(async (req, res) => {
    try {
        const prodRows = await pool.query(`SELECT product_name, image_filename, product_code, model_num1 FROM product_info p WHERE p.image_filename IS NOT NULL AND p.image_filename <> '' AND NOT EXISTS (SELECT 1 FROM images i WHERE i.title LIKE '%' || p.image_filename) LIMIT 5`);
        const imgRows = await pool.query(`SELECT title FROM images i WHERE NOT EXISTS (SELECT 1 FROM product_info p WHERE p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || p.image_filename) ORDER BY created_at DESC LIMIT 5`);
        res.json({ unlinkedProducts: prodRows.rows, unlinkedImages: imgRows.rows });
    } catch(e) { res.status(500).json({message: 'Error: ' + e.message}); }
}));
app.get('/api/products/template', isAuthenticated, (req, res) => {
    const header = "商品名,型番1,型番2,状態,カードのシリーズ,在庫,ECサイト価格,メルカリ価格,商品コード,商品画像名,メルカリ商品ID\n";
    const example = "テストカード,DM-01,,A,基本セット,10,100,300,CODE001,DM-01.jpg,mShopsID_12345\n";
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="template.csv"'); res.send('\uFEFF' + header + example);
});
app.post('/api/products/import', isAuthenticated, upload.single('csvFile'), apiHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'CSVファイルがありません' });
    const { category1, category2, category3 } = req.body;
    const c1 = category1 || '未分類'; const c2 = category2 || '-'; const c3 = category3 || '-';
    const csvData = req.file.buffer.toString('utf-8').replace(/^\uFEFF/, '');
    const records = parse(csvData, { columns: ['product_name','model_num1','model_num2','condition','series','stock','ec_price','mercari_price','product_code','image_filename','mercari_product_id'], from_line: 2, skip_empty_lines: true, trim: true });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const fileRes = await client.query('INSERT INTO csv_uploads (filename, category_1, category_2, category_3) VALUES ($1, $2, $3, $4) RETURNING id', [req.file.originalname, c1, c2, c3]);
        const uploadId = fileRes.rows[0].id;
        for (const row of records) {
            if (!row.product_code) continue;
            const query = `INSERT INTO product_info (product_name, model_num1, model_num2, condition, series, stock, ec_price, mercari_price, product_code, image_filename, csv_upload_id, mercari_product_id, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP) ON CONFLICT (product_code) DO UPDATE SET product_name=EXCLUDED.product_name, model_num1=EXCLUDED.model_num1, model_num2=EXCLUDED.model_num2, condition=EXCLUDED.condition, series=EXCLUDED.series, stock=EXCLUDED.stock, ec_price=EXCLUDED.ec_price, mercari_price=EXCLUDED.mercari_price, image_filename=EXCLUDED.image_filename, csv_upload_id=EXCLUDED.csv_upload_id, mercari_product_id=EXCLUDED.mercari_product_id, updated_at=CURRENT_TIMESTAMP`;
            const stock = parseInt(row.stock || '0'); const ec = parseInt(row.ec_price || '0'); const mer = parseInt(row.mercari_price || '0');
            await client.query(query, [row.product_name, row.model_num1, row.model_num2 || null, row.condition, row.series, stock, ec, mer, row.product_code, row.image_filename, uploadId, row.mercari_product_id || null]);
        }
        await client.query('COMMIT'); res.json({ message: `${req.file.originalname} を登録しました (${records.length}件)` });
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));
app.get('/api/products/files', isAuthenticated, apiHandler(async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM csv_uploads ORDER BY uploaded_at DESC'); res.json(rows); } catch (e) { res.json([]); } }));
app.put('/api/products/files/:id', isAuthenticated, apiHandler(async (req, res) => { const { filename, category1, category2, category3 } = req.body; await pool.query('UPDATE csv_uploads SET filename = $1, category_1 = $2, category_2 = $3, category_3 = $4 WHERE id = $5', [filename, category1, category2, category3, req.params.id]); res.json({ message: '変更しました' }); }));
app.delete('/api/products/files/:id', isAuthenticated, apiHandler(async (req, res) => { const client = await pool.connect(); try { await client.query('BEGIN'); await client.query('DELETE FROM product_info WHERE csv_upload_id = $1', [req.params.id]); await client.query('DELETE FROM csv_uploads WHERE id = $1', [req.params.id]); await client.query('COMMIT'); res.json({ message: '削除しました' }); } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); } }));
app.get('/api/products/files/:id/download', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query(`SELECT product_name, model_num1, model_num2, condition, series, stock, ec_price, mercari_price, product_code, image_filename, mercari_product_id FROM product_info WHERE csv_upload_id = $1 ORDER BY product_code`, [req.params.id]); if (rows.length === 0) return res.status(404).send('Data not found'); let csv = "商品名,型番1,型番2,状態,カードのシリーズ,在庫,ECサイト価格,メルカリ価格,商品コード,商品画像名,メルカリ商品ID\n"; rows.forEach(r => { csv += `"${r.product_name}","${r.model_num1}","${r.model_num2||''}","${r.condition}","${r.series}",${r.stock},${r.ec_price},${r.mercari_price},"${r.product_code}","${r.image_filename}","${r.mercari_product_id||''}"\n`; }); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename="backup_${req.params.id}.csv"`); res.status(200).send('\uFEFF' + csv); }));

// --- その他API ---
app.get('/api/search', isAuthenticated, apiHandler(async (req, res) => {
    const { cat1, cat2, cat3, folder, q, sort, order } = req.query;
    if (!q && (!cat1 || !cat2 || !cat3 || !folder)) return res.status(400).json({message: 'カテゴリを選択するか、検索ワードを入力してください'});
    const s = sort === 'title' ? 'i.title' : 'i.created_at'; const d = order === 'ASC' ? 'ASC' : 'DESC';
    let sql = `SELECT i.*, p.product_name, p.model_num1, p.model_num2, p.ec_price, p.mercari_price, p.stock FROM images i LEFT JOIN product_info p ON ((p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename)) OR (p.product_code IS NOT NULL AND p.product_code <> '' AND i.title LIKE '%' || TRIM(p.product_code) || '%') OR (p.model_num1 IS NOT NULL AND p.model_num1 <> '' AND i.title LIKE '%' || TRIM(p.model_num1) || '%')) WHERE 1=1`;
    let params = []; let pIdx = 1;
    if (cat1) { sql += ` AND i.category_1=$${pIdx++}`; params.push(cat1); }
    if (cat2) { sql += ` AND i.category_2=$${pIdx++}`; params.push(cat2); }
    if (cat3) { sql += ` AND i.category_3=$${pIdx++}`; params.push(cat3); }
    if (folder) { sql += ` AND i.folder_name=$${pIdx++}`; params.push(folder); }
    if (q) { const keywords = q.replace(/　/g, ' ').trim().split(/\s+/); keywords.forEach(word => { sql += ` AND (i.title ILIKE $${pIdx} OR p.product_name ILIKE $${pIdx} OR p.model_num1 ILIKE $${pIdx} OR p.model_num2 ILIKE $${pIdx} OR p.product_code ILIKE $${pIdx})`; params.push(`%${word}%`); pIdx++; }); }
    sql += ` ORDER BY ${s} ${d} LIMIT 300`; const { rows } = await pool.query(sql, params); res.json(rows);
}));

app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), apiHandler(async (req, res) => { const { category1, category2, category3, folderName } = req.body; if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'No files' }); const c1 = category1.trim(); const c2 = category2.trim(); const c3 = category3.trim(); const f = folderName.trim(); const values = [], params = []; let idx = 1; for (const file of req.files) { const name = Buffer.from(file.originalname, 'latin1').toString('utf8'); const key = `${c1}/${c2}/${c3}/${f}/${name}`; await s3Client.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: file.buffer, ContentType: file.mimetype })); const url = `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(key)}`; values.push(`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`); params.push(key, url, c1, c2, c3, f); } await pool.query(`INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) VALUES ${values.join(', ')}`, params); res.json({ message: `${req.files.length}件 保存完了` }); }));
app.get('/download-csv', isAuthenticated, apiHandler(async (req, res) => { const { folder, cat1, cat2, cat3 } = req.query; let sql = `SELECT i.*, p.product_name, p.model_num1, p.model_num2, p.ec_price, p.mercari_price, p.stock FROM images i LEFT JOIN product_info p ON (p.image_filename IS NOT NULL AND p.image_filename <> '' AND i.title LIKE '%' || TRIM(p.image_filename)) WHERE i.category_1=$1 AND i.category_2=$2 AND i.category_3=$3 AND i.folder_name=$4 ORDER BY i.title`; const { rows } = await pool.query(sql, [cat1, cat2, cat3, folder]); let csv = "大,中,小,フォルダ,ファイル名,商品名,型番1,型番2,EC価格,メルカリ価格,在庫,URL\n"; rows.forEach(r => { csv += `"${r.category_1}","${r.category_2}","${r.category_3}","${r.folder_name}","${r.title}","${r.product_name||''}","${r.model_num1||''}","${r.model_num2||''}","${r.ec_price||0}","${r.mercari_price||0}","${r.stock||0}","${r.url}"\n`; }); res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename="list.csv"`); res.status(200).send('\uFEFF' + csv); }));

const getList = (col) => apiHandler(async (req, res) => { const { rows } = await pool.query(`SELECT DISTINCT ${col} FROM images ORDER BY ${col}`); res.json(rows.map(r => r[col])); });
app.put('/api/image/:title', isAuthenticated, apiHandler(async (req, res) => { const { title } = req.params; const { category1, category2, category3, folderName } = req.body; const name = title.split('/').pop(); const newKey = `${category1}/${category2}/${category3}/${folderName}/${name}`; await s3Client.send(new CopyObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, CopySource: `${process.env.R2_BUCKET_NAME}/${title}`, Key: newKey })); await s3Client.send(new S3DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: title })); await pool.query(`UPDATE images SET category_1=$1, category_2=$2, category_3=$3, folder_name=$4, title=$5, url=$6 WHERE title=$7`, [category1, category2, category3, folderName, newKey, `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(newKey)}`, title]); res.json({ message: "移動完了" }); }));
app.delete('/api/folder/:name', isAuthenticated, apiHandler(async(req,res) => {const {rows}=await pool.query(`SELECT title FROM images WHERE folder_name=$1`,[req.params.name]); if(rows.length>0){ const keys=rows.map(r=>({Key:r.title})); for(let i=0;i<keys.length;i+=1000)await s3Client.send(new DeleteObjectsCommand({Bucket:process.env.R2_BUCKET_NAME,Delete:{Objects:keys.slice(i,i+1000)}})); } await pool.query(`DELETE FROM images WHERE folder_name=$1`,[req.params.name]); res.json({message:"削除完了"}); }));
app.put('/api/cat1/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_1=$1 WHERE category_1=$2', [req.body.newName, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/cat2/:c1/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_2=$1 WHERE category_1=$2 AND category_2=$3', [req.body.newName, req.params.c1, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/cat3/:c1/:c2/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_3=$1 WHERE category_1=$2 AND category_2=$3 AND category_3=$4', [req.body.newName, req.params.c1, req.params.c2, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/folder/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET folder_name=$1 WHERE folder_name=$2', [req.body.newName, req.params.old]); res.json({message:'OK'}); }));
app.delete('/api/cat1/:name', isAuthenticated, apiHandler(async(req, res) => { await pool.query(`DELETE FROM images WHERE category_1=$1`, [req.params.name]); res.json({message:'OK'}); }));
app.delete('/api/cat2/:c1/:name', isAuthenticated, apiHandler(async(req, res) => { await pool.query(`DELETE FROM images WHERE category_1=$1 AND category_2=$2`, [req.params.c1, req.params.name]); res.json({message:'OK'}); }));
app.delete('/api/cat3/:c1/:c2/:name', isAuthenticated, apiHandler(async(req, res) => { await pool.query(`DELETE FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3`, [req.params.c1, req.params.c2, req.params.name]); res.json({message:'OK'}); }));
app.delete('/api/personal/album/:name', isAuthenticated, apiHandler(async (req, res) => { await performDelete(res, "category_1='Private' AND category_2='Album' AND category_3='Photo' AND folder_name=$1", [req.params.name]); }));
app.get('/api/personal/download/:folder', isAuthenticated, apiHandler(async (req, res) => { const folder = req.params.folder; const { rows } = await pool.query(`SELECT title FROM images WHERE category_1='Private' AND category_2='Album' AND category_3='Photo' AND folder_name=$1`, [folder]); if (rows.length === 0) return res.status(404).send('Empty'); res.attachment(`${encodeURIComponent(folder)}.zip`); const archive = archiver('zip', { zlib: { level: 9 } }); archive.pipe(res); for (const row of rows) { try { const s3Item = await s3Client.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: row.title })); archive.append(s3Item.Body, { name: row.title.split('/').pop() }); } catch (e) {} } await archive.finalize(); }));
app.post('/api/analyze/:folder', isAuthenticated, apiHandler(async (req, res) => { res.status(200).send('CSV Dummy'); }));

app.listen(port, async () => { await createTable(); console.log(`Server running on ${port}`); });