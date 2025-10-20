// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand: S3DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const PgSession = require('connect-pg-simple')(session);
const flash = require('connect-flash');
const ejs = require('ejs');
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

// --- テンプレートエンジン(EJS) 設定 ---
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname);

// --- Middleware 設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(session({
    store: new PgSession({ pool: pool, tableName: 'user_sessions' }),
    secret: process.env.SESSION_SECRET || 'fallback_secret_set_in_env_variable',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' }
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// --- Passport 設定 ---
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (result.rows.length === 0) { return done(null, false, { message: 'ユーザー名が見つかりません。' }); }
            const user = result.rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) { return done(null, user); }
            else { return done(null, false, { message: 'パスワードが間違っています。' }); }
        } catch (err) { console.error('Passport Error:', err); return done(err); }
    }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]);
        if (result.rows.length > 0) { done(null, result.rows[0]); } else { done(null, false); }
    } catch (err) { console.error('Deserialize Error:', err); done(err); }
});

// --- DBテーブル自動作成関数 (4階層対応) ---
const createTable = async () => {
    const userQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`;
    const sessionQuery = `CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default","sess" json NOT NULL,"expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE); DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_sessions_pkey') THEN ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE; END IF; END $$; CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");`;
    const createQuery = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      category_1 VARCHAR(100) DEFAULT 'default_cat1',
      category_2 VARCHAR(100) DEFAULT 'default_cat2',
      category_3 VARCHAR(100) DEFAULT 'default_cat3',
      folder_name VARCHAR(100) DEFAULT 'default_folder'
    );`;
    const alterColumns = [
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`,
        `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`
    ];
    // 索引(INDEX)を作成するクエリ
    const createIndexes = [
        `CREATE INDEX IF NOT EXISTS idx_images_cat1 ON images (category_1);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2 ON images (category_1, category_2);`,
        `CREATE INDEX IF NOT EXISTS idx_images_cat1_cat2_cat3 ON images (category_1, category_2, category_3);`,
        `CREATE INDEX IF NOT EXISTS idx_images_folder_name ON images (folder_name);`,
        `CREATE INDEX IF NOT EXISTS idx_images_title_length_and_title ON images (length(title), title);`
    ];
    try {
        await pool.query(userQuery); await pool.query(sessionQuery); await pool.query(createQuery);
        for (const query of alterColumns) { await pool.query(query); }
        console.log('Database tables altered.');
        for (const query of createIndexes) { await pool.query(query); }
        console.log('Database indexes created.');
        console.log('Database tables ready.');
    } catch (err) { console.error('DB init error:', err); }
};

// --- ストレージ (R2) 接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// --- Multer (アップロード処理) 設定 (元のファイル名で直接保存) ---
const upload = multer({
    storage: multerS3({
        s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read',
        key: function (req, file, cb) {
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, originalName); // 元のファイル名でアップロード
        },
        contentType: multerS3.AUTO_CONTENT_TYPE
    }),
    fileFilter: (req, file, cb) => { if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});

// --- ログインチェック関数 ---
function isAuthenticated(req, res, next) { if (req.isAuthenticated()) { return next(); } res.redirect('/login'); }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要ルート ---
app.get('/login', (req, res) => { res.render('login.html', { messages: req.flash('error') }); });
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }));
app.get('/logout', (req, res, next) => { req.logout((err) => { if (err) { return next(err); } res.redirect('/login'); }); });

// --- ログイン必須ルート ---
app.get('/', isAuthenticated, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// アップロードAPI (/upload) (元のファイル名でそのまま保存)
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }
    console.log(`[Upload V3] Received ${req.files.length} files for ${category1}/${category2}/${category3}/${folderName}`);
    const cat1Trimmed = category1.trim(); const cat2Trimmed = category2.trim(); const cat3Trimmed = category3.trim(); const folderNameTrimmed = folderName.trim();
    const processedFiles = [];
    try {
        const insertPromises = [];
        for (const file of req.files) {
            const targetFilename = file.key; const targetUrl = `${r2PublicUrl}/${encodeURIComponent(targetFilename)}`; 
            insertPromises.push(pool.query( `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name) VALUES ($1, $2, $3, $4, $5, $6)`, [targetFilename, targetUrl, cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed] ));
            processedFiles.push(targetFilename); console.log(`[Upload V3] Saved ${targetFilename}`);
        }
        await Promise.all(insertPromises);
        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${processedFiles.length} 件を元のファイル名で保存しました。` });
    } catch (error) { console.error('[Upload V3] Error during processing:', error); res.status(500).json({ message: 'ファイル処理エラー' }); }
});

// CSV API (/download-csv) (拡張子削除済み, 自然順ソート)
app.get('/download-csv', isAuthenticated, async (req, res) => {
    try {
        const { folder } = req.query; let queryText; let queryParams;
        const orderByClause = 'ORDER BY length(title), title ASC'; // 自然順ソート

        if (folder) { queryText = `SELECT title, url, category_1, category_2, category_3, folder_name FROM images WHERE folder_name = $1 ${orderByClause}`; queryParams = [decodeURIComponent(folder)]; }
        else { queryText = `SELECT title, url, category_1, category_2, category_3, folder_name FROM images ORDER BY category_1, category_2, category_3, folder_name, length(title), title ASC`; queryParams = []; }
        
        const { rows } = await pool.query(queryText, queryParams); if (rows.length === 0) { return res.status(404).send('対象履歴なし'); }
        let csvContent = "大カテゴリ,中カテゴリ,小カテゴリ,フォルダ名,題名,URL\n";
        rows.forEach(item => { const c1=`"${(item.category_1||'').replace(/"/g,'""')}"`; const c2=`"${(item.category_2||'').replace(/"/g,'""')}"`; const c3=`"${(item.category_3||'').replace(/"/g,'""')}"`; const f=`"${(item.folder_name||'').replace(/"/g,'""')}"`; const titleWithoutExtension = item.title.substring(0, item.title.lastIndexOf('.')) || item.title; const t = `"${titleWithoutExtension.replace(/"/g, '""')}"`; const u=`"${item.url.replace(/"/g,'""')}"`; csvContent += `${c1},${c2},${c3},${f},${t},${u}\n`; });
        const fileName = folder ? `list_${decodeURIComponent(folder)}.csv` : 'list_all.csv'; const bom = '\uFEFF'; res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`); res.status(200).send(bom + csvContent);
    } catch (dbError) { console.error('CSV Error:', dbError); res.status(500).send('CSV生成失敗'); }
});

// --- ギャラリー用API (デバッグログ付き) ---
// ★ /api/cat1 を「本番コード」に戻す
app.get('/api/cat1', isAuthenticated, async (req, res) => {
    try {
        console.log("[API] GET /api/cat1 received");
        const query = 'SELECT DISTINCT category_1 FROM images ORDER BY category_1';
        const { rows } = await pool.query(query);
        console.log(`[API] /api/cat1 found ${rows.length} items`);
        res.json(rows.map(r => r.category_1));
    } catch (e) {
        console.error("!!!!! API /api/cat1 FAILED !!!!!", e);
        res.status(500).json({ message: 'Error fetching cat1' });
    }
});
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/cat2/${req.params.cat1} received`); const { rows } = await pool.query('SELECT DISTINCT category_2 FROM images WHERE category_1 = $1 ORDER BY category_2', [req.params.cat1]); console.log(`[API] /api/cat2 found ${rows.length}`); res.json(rows.map(r => r.category_2)); } catch (e) { console.error("!!!!! API /api/cat2 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat2' }); } });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/cat3/${req.params.cat1}/${req.params.cat2} received`); const { rows } = await pool.query('SELECT DISTINCT category_3 FROM images WHERE category_1 = $1 AND category_2 = $2 ORDER BY category_3', [req.params.cat1, req.params.cat2]); console.log(`[API] /api/cat3 found ${rows.length}`); res.json(rows.map(r => r.category_3)); } catch (e) { console.error("!!!!! API /api/cat3 FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching cat3' }); } });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/folders received`); const { rows } = await pool.query('SELECT DISTINCT folder_name FROM images WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 ORDER BY folder_name', [req.params.cat1, req.params.cat2, req.params.cat3]); console.log(`[API] /api/folders found ${rows.length}`); res.json(rows.map(r => r.folder_name)); } catch (e) { console.error("!!!!! API /api/folders FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching folders' }); } });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { try { console.log(`[API] /api/images/${req.params.folderName} received`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; const qT = `SELECT title, url FROM images WHERE folder_name = $1 ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; const { rows } = await pool.query(qT, [req.params.folderName]); console.log(`[API] /api/images found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/images FAILED !!!!!", e); res.status(500).json({ message: 'Error fetching images' }); } });
app.get('/api/search', isAuthenticated, async (req, res) => { const { folder, q } = req.query; console.log(`[API] /api/search received (folder: ${folder}, q: ${q})`); const sortBy = req.query.sort === 'title' ? 'title' : 'created_at'; const sortOrder = req.query.order === 'ASC' ? 'ASC' : 'DESC'; if (!folder) { return res.status(400).json({ message: 'フォルダ指定必須' }); } try { let qT; let qP; const oBC = `ORDER BY ${sortBy} ${sortOrder}, id ${sortOrder}`; if (q && q.trim() !== '') { const s = `%${q}%`; qT = `SELECT title, url FROM images WHERE folder_name = $1 AND title ILIKE $2 ${oBC}`; qP = [folder, s]; } else { qT = `SELECT title, url FROM images WHERE folder_name = $1 ${oBC}`; qP = [folder]; } const { rows } = await pool.query(qT, qP); console.log(`[API] /api/search found ${rows.length}`); res.json(rows); } catch (e) { console.error("!!!!! API /api/search FAILED !!!!!", e); res.status(500).json({ message: '検索失敗' }); } });

// --- カテゴリ・フォルダ編集API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { const { oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_1 = $1 WHERE category_1 = $2', [newName.trim(), oldName]); res.json({ message: `大カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat1 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { const { cat1, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_2 = $1 WHERE category_1 = $2 AND category_2 = $3', [newName.trim(), cat1, oldName]); res.json({ message: `中カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat2 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { const { cat1, cat2, oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET category_3 = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4', [newName.trim(), cat1, cat2, oldName]); res.json({ message: `小カテゴリ名変更完了` }); } catch (e) { console.error("Rename Cat3 Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { const { oldName } = req.params; const { newName } = req.body; if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'}); try { await pool.query('UPDATE images SET folder_name = $1 WHERE folder_name = $2', [newName.trim(), oldName]); res.json({ message: `フォルダ名変更完了` }); } catch (e) { console.error("Rename Folder Error:", e); res.status(500).json({ message: '名前変更失敗' }); } });

// --- カテゴリ・フォルダ削除API ---
async function performDelete(res, conditions, params, itemDescription) {
    try {
        const { rows } = await pool.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            for (let i = 0; i < objectsToDelete.length; i += 1000) { const chunk = objectsToDelete.slice(i, i + 1000); const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: chunk } }); await s3Client.send(deleteCommand); console.log(`Deleted ${chunk.length} R2 objects`); }
        }
        const deleteResult = await pool.query(`DELETE FROM images WHERE ${conditions}`, params); console.log(`Deleted ${deleteResult.rowCount} DB records for ${itemDescription}`);
        res.json({ message: `${itemDescription} 削除完了` });
    } catch (error) { console.error(`Delete Error:`, error); res.status(500).json({ message: '削除失敗' }); }
}
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`); });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`); });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`); });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { await performDelete(res, 'folder_name = $1', [req.params.name], `フォルダ「${req.params.name}」`); });

// --- 画像移動API ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params; const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName) { return res.status(400).json({ message: '移動先指定必須' }); }
    try {
        const updateQuery = `UPDATE images SET category_1 = $1, category_2 = $2, category_3 = $3, folder_name = $4 WHERE title = $5`;
        const result = await pool.query(updateQuery, [ category1.trim(), category2.trim(), category3.trim(), folderName.trim(), imageTitle ]);
        if (result.rowCount === 0) { return res.status(404).json({ message: '画像なし' }); }
        res.json({ message: `画像移動完了` });
    } catch (error) { console.error(`Move Image Error:`, error); res.status(500).json({ message: '移動失敗' }); }
});

// --- 解析API (Tesseract.js 版) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params; console.log(`[Analyze Tesseract] Req: ${folderName}`); let worker;
    const getImageBuffer = (url) => new Promise((resolve, reject) => { https.get(url, (response) => { if (response.statusCode !== 200) return reject(new Error(`Status Code: ${response.statusCode}`)); const d = []; response.on('data', c => d.push(c)); response.on('end', () => resolve(Buffer.concat(d))); }).on('error', reject); });
    const runOCR = async (buffer, regionName) => { try { const pBuf = await sharp(buffer).grayscale().toBuffer(); const { data: { text } } = await worker.recognize(pBuf); console.log(`[Tesseract] OCR Ok [${regionName}]`); return text.replace(/"/g, '""').replace(/\n/g, ' ').trim(); } catch (e) { console.error(`[Tesseract] OCR Err [${regionName}]:`, e.message); return '*** OCR ERR ***'; } };
    try {
        const { rows } = await pool.query('SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title', [folderName]); if (rows.length === 0) return res.status(404).json({ message: '画像なし' });
        console.log(`[Tesseract] Found ${rows.length} images`);
        worker = await createWorker('jpn+eng', 1, { logger: m => console.log(`[Tesseract] ${m.status}: ${m.progress * 100}%`) }); console.log('[Tesseract] Worker init.');
        let analysisResults = [];
        for (const image of rows) {
            console.log(`[Tesseract] Processing: ${image.title}`); const result = { filename: image.title, cardName: '', cardText: '', power: '', cost: '', expansion: '' };
            try {
                const imageBuffer = await getImageBuffer(image.url); const metadata = await sharp(imageBuffer).metadata(); const w = metadata.width; const h = metadata.height;
                const regions = { cardName: { left: Math.round(w * 0.1), top: Math.round(h * 0.05), width: Math.round(w * 0.8), height: Math.round(h * 0.08) }, cost: { left: Math.round(w * 0.03), top: Math.round(h * 0.03), width: Math.round(w * 0.1), height: Math.round(h * 0.08) }, cardText: { left: Math.round(w * 0.1), top: Math.round(h * 0.55), width: Math.round(w * 0.8), height: Math.round(h * 0.3) }, power: { left: Math.round(w * 0.05), top: Math.round(h * 0.88), width: Math.round(w * 0.25), height: Math.round(h * 0.08) }, expansion:{ left: Math.round(w * 0.65), top: Math.round(h * 0.88), width: Math.round(w * 0.25), height: Math.round(h * 0.05) }, };
                if (regions.cardName) result.cardName = await runOCR(await sharp(imageBuffer).extract(regions.cardName).toBuffer(), 'Name');
                if (regions.cost) result.cost = await runOCR(await sharp(imageBuffer).extract(regions.cost).toBuffer(), 'Cost');
                if (regions.cardText) result.cardText = await runOCR(await sharp(imageBuffer).extract(regions.cardText).toBuffer(), 'Text');
                if (regions.power) result.power = await runOCR(await sharp(imageBuffer).extract(regions.power).toBuffer(), 'Power');
                if (regions.expansion) result.expansion = await runOCR(await sharp(imageBuffer).extract(regions.expansion).toBuffer(), 'Expansion');
                analysisResults.push(result); console.log(`[Tesseract] Processed ${image.title}`);
            } catch (imgError) { console.error(`[Tesseract] Image Err ${image.title}:`, imgError.message); analysisResults.push({ ...result, cardName: '*** IMG ERR ***' }); }
        }
        await worker.terminate(); worker = null; console.log('[Tesseract] Worker terminated.');
        let csvContent = "ファイル名,カード名,コスト,テキスト,パワー,エキスパンション\n"; analysisResults.forEach(r => { csvContent += `"${r.filename}","${r.cardName}","${r.cost}","${r.cardText}","${r.power}","${r.expansion}"\n`; });
        const fileName = `analysis_tesseract_${folderName}.csv`; const bom = '\uFEFF'; res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`); res.status(200).send(bom + csvContent); console.log(`[Tesseract] Sent CSV`);
    } catch (error) { console.error(`[Tesseract] Error:`, error); if (worker) { try { await worker.terminate(); } catch (e) { console.error('Error terminating worker:', e);} } res.status(500).json({ message: '解析エラー発生' }); }
});

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});