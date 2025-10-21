// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
// --- ▼ 認証関連のライブラリ ▼ ---
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const PgStore = require('connect-pg-simple')(session); // DBにセッションを保存
// --- ▲ 認証関連のライブラリ ▲ ---
const { createWorker } = require('tesseract.js'); // OCR
const sharp = require('sharp'); // 画像処理
const https = require('https'); // 画像URL取得

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Render
});

// --- Middleware 設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- ▼ 認証機能ここから (Session と Passport の設定) ▼ ---
app.use(session({
    store: new PgStore({ pool: pool, tableName: 'user_sessions' }),
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: false,
    proxy: true, 
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, 
        secure: 'auto', 
        httpOnly: true,
        sameSite: 'lax' 
    } 
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) { return done(null, false, { message: 'ユーザー名またはパスワードが違います。' }); }
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) { return done(null, user); } 
            else { return done(null, false, { message: 'ユーザー名またはパスワードが違います。' }); }
        } catch (error) { return done(error); }
    }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (rows.length > 0) { done(null, rows[0]); } 
        else { done(new Error('User not found')); }
    } catch (error) { done(error); }
});
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.status(401).json({ message: 'ログインが必要です。' });
}
// --- ▲ 認証機能ここまで ▲ ---


// --- ▼▼▼ DBテーブル自動作成関数 (folders テーブル追加) ▼▼▼ ---
const createTable = async () => {
    const createImagesTable = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      category_1 VARCHAR(100) DEFAULT 'default_cat1',
      category_2 VARCHAR(100) DEFAULT 'default_cat2',
      category_3 VARCHAR(100) DEFAULT 'default_cat3',
      folder_name VARCHAR(100) DEFAULT 'default_folder'
    );`;
    const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;
    const createSessionTable = `
    CREATE TABLE IF NOT EXISTS "user_sessions" (
      "sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE);
    ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
    CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");
    `;
    
    // ★ フォルダの並び順を保存するテーブルを新規追加
    const createFoldersTable = `
    CREATE TABLE IF NOT EXISTS folders (
      id SERIAL PRIMARY KEY,
      category_1 VARCHAR(100) NOT NULL,
      category_2 VARCHAR(100) NOT NULL,
      category_3 VARCHAR(100) NOT NULL,
      folder_name VARCHAR(100) NOT NULL,
      sort_order INTEGER DEFAULT 0,
      UNIQUE(category_1, category_2, category_3, folder_name)
    );
    `;

    const alterColumns = [ /* (変更なし) */ ];
    
    const createIndexes = [
        `CREATE INDEX IF NOT EXISTS idx_images_cat1 ON images (category_1);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2 ON images (category_1, category_2);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2_cat3 ON images (category_1, category_2, category_3);`,
        `CREATE INDEX IF NOT EXISTS idx_images_folder_name ON images (folder_name);`,
        `CREATE INDEX IF NOT EXISTS idx_images_title_length_and_title ON images (length(title), title);`,
        // ★ 新しい folders テーブル用のインデックス
        `CREATE INDEX IF NOT EXISTS idx_folders_cats ON folders (category_1, category_2, category_3);`
    ];

    try {
        await pool.query(createImagesTable);
        await pool.query(createUsersTable);
        await pool.query(createSessionTable);
        await pool.query(createFoldersTable); // ★ 新規テーブル作成
        
        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables altered.');
        for (const query of createIndexes) { await pool.query(query); } // ★ インデックス作成
        console.log('Database indexes created.');
        console.log('Database tables ready.');
    } catch (err) { console.error('DB init error:', err); }
};
// --- ▲▲▲ DBテーブル自動作成関数 (folders テーブル追加) ▲▲▲ ---

// --- ストレージ (R2) 接続 (変更なし) ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer (アップロード処理) 設定 (変更なし) ---
const upload = multer({
    storage: multerS3({
        s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read',
        key: function (req, file, cb) {
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, originalName); 
        },
        contentType: multerS3.AUTO_CONTENT_TYPE
    }),
    fileFilter: (req, file, cb) => { if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証ルート (変更なし) ---
app.get('/login', (req, res) => { res.sendFile(path.join(__dirname, 'login.html')); });
app.get('/register', (req, res) => { res.sendFile(path.join(__dirname, 'register.html')); });
app.post('/api/auth/register', async (req, res) => { /* (変更なし) */ });
app.post('/api/auth/login', passport.authenticate('local'), (req, res) => { /* (変更なし) */ });
app.post('/api/auth/logout', (req, res, next) => { /* (変更なし) */ });
app.get('/api/auth/check', (req, res) => { /* (変更なし) */ });

// ★ メインページ ( / ) (変更なし)
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ==================================================================
// ▼▼▼ アップロードAPI (/upload) ▼▼▼
// ==================================================================
// --- ▼▼▼ 修正 (folders テーブルにも INSERT) ▼▼▼ ---
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }
    const cat1Trimmed = category1.trim(); const cat2Trimmed = category2.trim(); const cat3Trimmed = category3.trim(); const folderNameTrimmed = folderName.trim();
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. images テーブルへのバルクインサート (既存ロジック)
        const values = []; const params = []; let paramIndex = 1;
        for (const file of req.files) {
            const targetFilename = file.key;
            const targetUrl = `${r2PublicUrl}/${encodeURIComponent(targetFilename)}`;
            values.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
            params.push(targetFilename, targetUrl, cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed);
        }
        const queryText = `
            INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) 
            VALUES ${values.join(', ')}
        `;
        await client.query(queryText, params);
        
        // 2. ★ folders テーブルにフォルダが存在することを保証する
        const folderSyncQuery = `
            INSERT INTO folders (category_1, category_2, category_3, folder_name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING
        `;
        await client.query(folderSyncQuery, [cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed]);
        
        await client.query('COMMIT');
        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${req.files.length} 件を元のファイル名で保存しました。` });
    } catch (error) { 
        await client.query('ROLLBACK');
        console.error('[Upload V3] Error during processing:', error); 
        res.status(500).json({ message: 'ファイル処理エラー' }); 
    } finally {
        client.release();
    }
});
// --- ▲▲▲ 修正 (folders テーブルにも INSERT) ▲▲▲ ---

// ==================================================================
// ▼▼▼ CSV API (/download-csv) (変更なし) ▼▼▼
// ==================================================================
app.get('/download-csv', isAuthenticated, async (req, res) => { /* (変更なし) */ });


// ==================================================================
// ▼▼▼ ギャラリー・編集・削除 API ▼▼▼
// ==================================================================
// --- Cat1, Cat2, Cat3 API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- ▼▼▼ /api/folders を修正 (folders テーブルから取得) ▼▼▼ ---
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { 
    const { cat1, cat2, cat3 } = req.params;
    const client = await pool.connect();
    try { 
        await client.query('BEGIN');
        
        // 1. images テーブルに存在するが folders テーブルにないフォルダを同期
        const syncQuery = `
            INSERT INTO folders (category_1, category_2, category_3, folder_name)
            SELECT DISTINCT category_1, category_2, category_3, folder_name
            FROM images
            WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3
            ON CONFLICT (category_1, category_2, category_3, folder_name) DO NOTHING
        `;
        await client.query(syncQuery, [cat1, cat2, cat3]);
        
        // 2. folders テーブルから並び順 (sort_order) で取得
        const selectQuery = `
            SELECT folder_name 
            FROM folders
            WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3
            ORDER BY sort_order ASC, folder_name ASC
        `;
        const { rows } = await client.query(selectQuery, [cat1, cat2, cat3]);
        
        await client.query('COMMIT');
        res.json(rows.map(r => r.folder_name));
    } catch (e) { 
        await client.query('ROLLBACK');
        console.error("!!!!! API /api/folders FAILED !!!!!", e); 
        res.status(500).json({ message: 'Error fetching folders' }); 
    } finally {
        client.release();
    }
});
// --- ▲▲▲ /api/folders を修正 ▲▲▲ ---

// --- ▼▼▼ フォルダ並び替えAPIを新規追加 ▼▼▼ ---
app.post('/api/folders/reorder', isAuthenticated, async (req, res) => {
    const { category1, category2, category3, orderedFolderNames } = req.body;
    
    if (!category1 || !category2 || !category3 || !Array.isArray(orderedFolderNames)) {
        return res.status(400).json({ message: '不正なリクエストです' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 配列の順序 (index) を使って sort_order を更新
        for (let i = 0; i < orderedFolderNames.length; i++) {
            const folderName = orderedFolderNames[i];
            const sortOrder = i; // 0ベースのインデックスを並び順として保存
            
            await client.query(
                `UPDATE folders 
                 SET sort_order = $1 
                 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4 AND folder_name = $5`,
                [sortOrder, category1, category2, category3, folderName]
            );
        }
        
        await client.query('COMMIT');
        res.json({ message: 'フォルダの並び順を保存しました。' });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("!!!!! API /api/folders/reorder FAILED !!!!!", e);
        res.status(500).json({ message: '並び順の保存に失敗しました。' });
    } finally {
        client.release();
    }
});
// --- ▲▲▲ フォルダ並び替えAPIを新規追加 ▲▲▲ ---

app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- カテゴリ・フォルダ編集API (Cat1, 2, 3) (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- ▼▼▼ フォルダ名変更 (PUT /api/folder) を修正 (folders テーブルも更新) ▼▼▼ ---
// APIパスを /:oldName から /:cat1/:cat2/:cat3/:oldName に変更
app.put('/api/folder/:cat1/:cat2/:cat3/:oldName', isAuthenticated, async (req, res) => { 
    const { cat1, cat2, cat3, oldName } = req.params; 
    const { newName } = req.body;
    if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'});
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const newNameTrimmed = newName.trim();
        
        // 1. images テーブルを更新
        await client.query(
            'UPDATE images SET folder_name = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4 AND folder_name = $5', 
            [newNameTrimmed, cat1, cat2, cat3, oldName]
        );
        // 2. folders テーブルを更新
        await client.query(
            'UPDATE folders SET folder_name = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4 AND folder_name = $5',
            [newNameTrimmed, cat1, cat2, cat3, oldName]
        );
        
        await client.query('COMMIT');
        res.json({ message: `フォルダ名変更完了` }); 
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Rename Folder Error:", e); 
        res.status(500).json({ message: '名前変更失敗' }); 
    } finally {
        client.release();
    }
});
// --- ▲▲▲ フォルダ名変更 (PUT /api/folder) を修正 ▲▲▲ ---

// --- ▼▼▼ performDelete 関数 と 削除API群を修正 (folders テーブルも削除) ▼▼▼ ---
async function performDelete(res, conditions, params, itemDescription, levelData = {}) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. R2からオブジェクト削除 (既存ロジック)
        const { rows } = await client.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            for (let i = 0; i < objectsToDelete.length; i += 1000) { 
                const chunk = objectsToDelete.slice(i, i + 1000); 
                const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: chunk } }); 
                await s3Client.send(deleteCommand); 
                console.log(`Deleted ${chunk.length} R2 objects`); 
            }
        }
        
        // 2. images テーブルから削除
        const deleteResult = await client.query(`DELETE FROM images WHERE ${conditions}`, params); 
        console.log(`Deleted ${deleteResult.rowCount} DB records for ${itemDescription}`);
        
        // 3. ★ levelData があれば、関連する folders テーブルの行も削除
        if (levelData.level === 1) { // 大カテゴリ
            await client.query(`DELETE FROM folders WHERE category_1 = $1`, [levelData.name]);
        } else if (levelData.level === 2) { // 中カテゴリ
            await client.query(`DELETE FROM folders WHERE category_1 = $1 AND category_2 = $2`, [levelData.cat1, levelData.name]);
        } else if (levelData.level === 3) { // 小カテゴリ
            await client.query(`DELETE FROM folders WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3`, [levelData.cat1, levelData.cat2, levelData.name]);
        } else if (levelData.level === 4) { // フォルダ
            await client.query(`DELETE FROM folders WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 AND folder_name = $4`, [levelData.cat1, levelData.cat2, levelData.cat3, levelData.name]);
        }
        
        await client.query('COMMIT');
        res.json({ message: `${itemDescription} 削除完了` });
    } catch (error) { 
        await client.query('ROLLBACK');
        console.error(`Delete Error:`, error); 
        res.status(500).json({ message: '削除失敗' }); 
    } finally {
        client.release();
    }
}
// 削除APIの呼び出しを修正
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { 
    await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`, {level: 1, name: req.params.name}); 
});
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { 
    await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`, {level: 2, cat1: req.params.cat1, name: req.params.name}); 
});
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { 
    await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`, {level: 3, cat1: req.params.cat1, cat2: req.params.cat2, name: req.params.name}); 
});
// フォルダ削除APIのパスを /:name から /:cat1/:cat2/:cat3/:name に変更
app.delete('/api/folder/:cat1/:cat2/:cat3/:name', isAuthenticated, async (req, res) => { 
    const { cat1, cat2, cat3, name } = req.params;
    await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3 AND folder_name = $4', [cat1, cat2, cat3, name], `フォルダ「${name}」`, {level: 4, cat1, cat2, cat3, name}); 
});
// --- ▲▲▲ performDelete 関数 と 削除API群を修正 ▲▲▲ ---


// --- 画像移動API (変更なし) ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* (変更なし) */ });

// --- 解析API (変更なし) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => { /* (変更なし) */ });


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});