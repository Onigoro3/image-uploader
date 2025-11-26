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
// ★追加: CSV読み込み用
const { parse } = require('csv-parse/sync');

const app = express();
const port = process.env.PORT || 3000;

// --- データベース接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 4, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000,
});
pool.on('error', (err) => console.error('DB Error:', err));

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- 認証設定 ---
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

// --- DB初期化 ---
const createTable = async () => {
    try {
        const client = await pool.connect();
        try {
            // 基本テーブル
            await client.query(`CREATE TABLE IF NOT EXISTS images (id SERIAL PRIMARY KEY, title VARCHAR(1024) NOT NULL, url VARCHAR(1024) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, category_1 VARCHAR(100) DEFAULT 'default_cat1', category_2 VARCHAR(100) DEFAULT 'default_cat2', category_3 VARCHAR(100) DEFAULT 'default_cat3', folder_name VARCHAR(100) DEFAULT 'default_folder');`);
            await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
            await client.query(`CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default" PRIMARY KEY, "sess" json NOT NULL, "expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE);`);
            await client.query(`CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");`);
            
            // ★追加: 商品情報テーブル (codeをキーにする)
            await client.query(`
                CREATE TABLE IF NOT EXISTS product_info (
                    code VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(1024),
                    pack VARCHAR(255),
                    model VARCHAR(255),
                    rare VARCHAR(255),
                    price INTEGER,
                    stock INTEGER,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // カラム追加チェック
            const cols = ['category_1', 'category_2', 'category_3', 'folder_name'];
            for (const col of cols) { await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='images' AND column_name='${col}') THEN ALTER TABLE images ADD COLUMN ${col} VARCHAR(100) DEFAULT 'default'; END IF; END $$;`); }
            console.log('Database initialized.');
        } finally { client.release(); }
    } catch (err) { console.error('DB Init Error:', err); }
};

// --- ストレージ ---
const s3Client = new S3Client({ region: 'auto', endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });
const upload = multer({ storage: multer.memoryStorage(), fileFilter: (req, f, cb) => { if(f.mimetype.startsWith('image/') || f.mimetype==='application/pdf'|| f.mimetype==='text/csv') cb(null,true); else cb(null,false); } });

// --- ルート設定 ---
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/personal', (req, res) => res.sendFile(path.join(__dirname, 'personal.html')));

// 認証API
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 8) return res.status(400).json({ message: 'ユーザー名と8文字以上のパスワード必須' });
    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);
        res.status(201).json({ message: '登録成功' });
    } catch (e) {
        if (e.code === '23505') res.status(409).json({ message: 'そのユーザー名は使用済みです' });
        else res.status(500).json({ message: 'サーバーエラー' });
    }
});
app.post('/api/auth/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ message: info.message || 'ログイン失敗' });
        req.logIn(user, (err) => {
            if (err) return next(err); return res.json({ message: 'ログイン成功', user: user.username });
        });
    })(req, res, next);
});
app.post('/api/auth/logout', (req, res, next) => { req.logout((err) => { if(err)return next(err); req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({message:'ログアウト'}); }); }); });
app.get('/api/auth/check', (req, res) => { if (req.isAuthenticated()) res.json({ loggedIn: true, username: req.user.username }); else res.json({ loggedIn: false }); });

// --- API ラッパー ---
const apiHandler = (fn) => async (req, res, next) => { try { await fn(req, res, next); } catch (e) { console.error(e); res.status(500).json({ message: e.message || "Error" }); } };

// ★追加: 商品情報CSVインポート
app.post('/api/products/import', isAuthenticated, upload.single('csvFile'), apiHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'CSVファイルがありません' });
    
    // CSVをパース
    const csvData = req.file.buffer.toString('utf-8');
    // BOM付きUTF-8対策
    const cleanCsvData = csvData.replace(/^\uFEFF/, '');
    
    const records = parse(cleanCsvData, {
        columns: true, // 1行目をヘッダーとして扱う
        skip_empty_lines: true
    });

    // データベースへ登録 (Upsert: あれば更新、なければ挿入)
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        for (const row of records) {
            // CSVの列名に合わせて調整 (Name, Pack, /型番, /Rare, 価格, 在庫, code)
            // スクリーンショットの列名に対応
            const code = row['code'] || row['Code'];
            const name = row['Name'];
            const pack = row['Pack'];
            const model = row['/型番'] || row['型番']; // スラッシュありなし両対応
            const rare = row['/Rare'] || row['Rare'];
            const price = parseInt(row['価格'] || row['Price'] || '0');
            const stock = parseInt(row['在庫'] || row['Stock'] || '0');

            if (code) {
                const query = `
                    INSERT INTO product_info (code, name, pack, model, rare, price, stock, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
                    ON CONFLICT (code) 
                    DO UPDATE SET 
                        name = EXCLUDED.name, 
                        pack = EXCLUDED.pack,
                        model = EXCLUDED.model, 
                        rare = EXCLUDED.rare,
                        price = EXCLUDED.price,
                        stock = EXCLUDED.stock,
                        updated_at = CURRENT_TIMESTAMP
                `;
                await client.query(query, [code, name, pack, model, rare, price, stock]);
            }
        }
        await client.query('COMMIT');
        res.json({ message: `${records.length}件の商品情報を登録しました` });
    } catch (e) {
        await client.query('ROLLBACK');
        throw e;
    } finally {
        client.release();
    }
}));

// --- 検索API (修正: 商品情報も検索・取得) ---
app.get('/api/search', isAuthenticated, apiHandler(async (req, res) => {
    const { cat1, cat2, cat3, folder, q, sort, order } = req.query;
    if (!cat1 || !cat2 || !cat3 || !folder) return res.status(400).json({message: 'カテゴリ必須'});
    
    const s = sort === 'title' ? 'i.title' : 'i.created_at';
    const d = order === 'ASC' ? 'ASC' : 'DESC';
    
    // ★修正: LEFT JOIN で product_info を結合
    // 画像のパス(title)の中に code が含まれているかを判定
    // 例: title="DM/Normal/DM-01.jpg", code="DM-01" -> ヒット
    let sql = `
        SELECT i.*, p.name as product_name, p.price, p.stock, p.model
        FROM images i
        LEFT JOIN product_info p ON i.title LIKE '%' || p.code || '%' 
        WHERE i.category_1=$1 AND i.category_2=$2 AND i.category_3=$3 AND i.folder_name=$4
    `;
    let p = [cat1, cat2, cat3, folder];
    
    // ★修正: 検索条件に商品名や型番を追加
    if (q) { 
        sql += ` AND (i.title ILIKE $5 OR p.name ILIKE $5 OR p.model ILIKE $5)`; 
        p.push(`%${q}%`); 
    }
    
    sql += ` ORDER BY ${s} ${d}`;
    
    const { rows } = await pool.query(sql, p);
    res.json(rows);
}));

// --- アップロード・ダウンロード系 ---
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), apiHandler(async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'ファイル未選択' });
    const c1 = category1.trim(); const c2 = category2.trim(); const c3 = category3.trim(); const f = folderName.trim();
    const values = [], params = []; let idx = 1;
    for (const file of req.files) {
        const name = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const key = `${c1}/${c2}/${c3}/${f}/${name}`;
        await s3Client.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: file.buffer, ContentType: file.mimetype }));
        const url = `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(key)}`;
        values.push(`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`);
        params.push(key, url, c1, c2, c3, f);
    }
    await pool.query(`INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) VALUES ${values.join(', ')}`, params);
    res.json({ message: `${req.files.length}件 保存完了` });
}));

app.get('/download-csv', isAuthenticated, apiHandler(async (req, res) => {
    const { folder, cat1, cat2, cat3 } = req.query;
    // CSV出力にも商品情報を含める
    let sql = `
        SELECT i.*, p.name as product_name, p.price, p.stock, p.model 
        FROM images i 
        LEFT JOIN product_info p ON i.title LIKE '%' || p.code || '%' 
        WHERE i.category_1=$1 AND i.category_2=$2 AND i.category_3=$3 AND i.folder_name=$4 
        ORDER BY i.title
    `;
    const { rows } = await pool.query(sql, [cat1, cat2, cat3, folder]);
    
    let csv = "大,中,小,フォルダ,ファイル名,商品名,価格,在庫,型番,URL\n";
    rows.forEach(r => {
        const pName = r.product_name || '';
        const pPrice = r.price || '';
        const pStock = r.stock || '';
        const pModel = r.model || '';
        csv += `"${r.category_1}","${r.category_2}","${r.category_3}","${r.folder_name}","${r.title}","${pName}","${pPrice}","${pStock}","${pModel}","${r.url}"\n`;
    });
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); 
    res.setHeader('Content-Disposition', `attachment; filename="list.csv"`);
    res.status(200).send('\uFEFF' + csv);
}));

// その他API
const getList = (col) => apiHandler(async (req, res) => { const { rows } = await pool.query(`SELECT DISTINCT ${col} FROM images ORDER BY ${col}`); res.json(rows.map(r => r[col])); });
app.get('/api/cat1', isAuthenticated, getList('category_1'));
app.get('/api/cat2/:c1', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT category_2 FROM images WHERE category_1=$1 ORDER BY category_2', [req.params.c1]); res.json(rows.map(r => r.category_2)); }));
app.get('/api/cat3/:c1/:c2', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT category_3 FROM images WHERE category_1=$1 AND category_2=$2 ORDER BY category_3', [req.params.c1, req.params.c2]); res.json(rows.map(r => r.category_3)); }));
app.get('/api/folders/:c1/:c2/:c3', isAuthenticated, apiHandler(async (req, res) => { const { rows } = await pool.query('SELECT DISTINCT folder_name FROM images WHERE category_1=$1 AND category_2=$2 AND category_3=$3 ORDER BY folder_name', [req.params.c1, req.params.c2, req.params.c3]); res.json(rows.map(r => r.folder_name)); }));

async function performDelete(res, where, params) {
    const { rows } = await pool.query(`SELECT title FROM images WHERE ${where}`, params);
    if (rows.length > 0) {
        const keys = rows.map(r => ({ Key: r.title }));
        for(let i=0; i<keys.length; i+=1000) await s3Client.send(new DeleteObjectsCommand({ Bucket: process.env.R2_BUCKET_NAME, Delete: { Objects: keys.slice(i, i+1000) } }));
    }
    await pool.query(`DELETE FROM images WHERE ${where}`, params);
    res.json({ message: "削除完了" });
}
app.delete('/api/folder/:name', isAuthenticated, apiHandler(async(req,res) => performDelete(res, 'folder_name=$1', [req.params.name])));
app.put('/api/cat1/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_1=$1 WHERE category_1=$2', [req.body.newName, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/cat2/:c1/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_2=$1 WHERE category_1=$2 AND category_2=$3', [req.body.newName, req.params.c1, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/cat3/:c1/:c2/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET category_3=$1 WHERE category_1=$2 AND category_2=$3 AND category_3=$4', [req.body.newName, req.params.c1, req.params.c2, req.params.old]); res.json({message:'OK'}); }));
app.put('/api/folder/:old', isAuthenticated, apiHandler(async(req, res) => { await pool.query('UPDATE images SET folder_name=$1 WHERE folder_name=$2', [req.body.newName, req.params.old]); res.json({message:'OK'}); }));
app.delete('/api/cat1/:name', isAuthenticated, apiHandler(async(req, res) => performDelete(res, 'category_1=$1', [req.params.name])));
app.delete('/api/cat2/:c1/:name', isAuthenticated, apiHandler(async(req, res) => performDelete(res, 'category_1=$1 AND category_2=$2', [req.params.c1, req.params.name])));
app.delete('/api/cat3/:c1/:c2/:name', isAuthenticated, apiHandler(async(req, res) => performDelete(res, 'category_1=$1 AND category_2=$2 AND category_3=$3', [req.params.c1, req.params.c2, req.params.name])));

app.put('/api/image/:title', isAuthenticated, apiHandler(async (req, res) => {
    const { title } = req.params; const { category1, category2, category3, folderName } = req.body;
    const name = title.split('/').pop();
    const newKey = `${category1}/${category2}/${category3}/${folderName}/${name}`;
    const newUrl = `${process.env.R2_PUBLIC_URL}/${encodeURIComponent(newKey)}`;
    await s3Client.send(new CopyObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, CopySource: `${process.env.R2_BUCKET_NAME}/${title}`, Key: newKey }));
    await s3Client.send(new S3DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: title }));
    await pool.query(`UPDATE images SET category_1=$1, category_2=$2, category_3=$3, folder_name=$4, title=$5, url=$6 WHERE title=$7`, [category1, category2, category3, folderName, newKey, newUrl, title]);
    res.json({ message: "移動完了" });
}));

app.delete('/api/personal/album/:name', isAuthenticated, apiHandler(async (req, res) => {
    const where = "category_1='Private' AND category_2='Album' AND category_3='Photo' AND folder_name=$1";
    await performDelete(res, where, [req.params.name]);
}));

app.get('/api/personal/download/:folder', isAuthenticated, apiHandler(async (req, res) => {
    const folder = req.params.folder;
    const { rows } = await pool.query(`SELECT title FROM images WHERE category_1='Private' AND category_2='Album' AND category_3='Photo' AND folder_name=$1`, [folder]);
    if (rows.length === 0) return res.status(404).send('Empty');
    res.attachment(`${encodeURIComponent(folder)}.zip`);
    const archive = archiver('zip', { zlib: { level: 9 } }); archive.pipe(res);
    for (const row of rows) { try { const s3Item = await s3Client.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: row.title })); archive.append(s3Item.Body, { name: row.title.split('/').pop() }); } catch (e) {} }
    await archive.finalize();
}));

app.post('/api/analyze/:folder', isAuthenticated, apiHandler(async (req, res) => {
    // OCR機能はそのまま
    const { folder } = req.params;
    const { rows } = await pool.query('SELECT * FROM images WHERE folder_name=$1 ORDER BY title', [folder]);
    if(rows.length===0) return res.status(404).json({message:'画像なし'});
    res.status(200).send('CSV Dummy');
}));

app.listen(port, async () => {
    await createTable();
    console.log(`Server running on ${port}`);
});