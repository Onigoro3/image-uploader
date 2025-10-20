// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
// ▼▼▼ R2/S3のコピー・削除コマンドは不要なものを削除 ▼▼▼
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
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

// --- DB接続, Middleware, Passport, DBテーブル作成 (変更なし) ---
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
app.engine('html', ejs.renderFile); app.set('view engine', 'html'); app.set('views', __dirname);
app.use(express.json()); app.use(express.urlencoded({ extended: false }));
app.use(session({ store: new PgSession({ pool: pool, tableName: 'user_sessions' }), secret: process.env.SESSION_SECRET || 'fallback_secret_set_in_env_variable', resave: false, saveUninitialized: false, cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' } }));
app.use(flash()); app.use(passport.initialize()); app.use(passport.session());
passport.use(new LocalStrategy( async (username, password, done) => { try { const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]); if (r.rows.length === 0) { return done(null, false, { message: 'ユーザー名なし' }); } const user = r.rows[0]; const i = await bcrypt.compare(password, user.password_hash); if (i) { return done(null, user); } else { return done(null, false, { message: 'パスワード違い' }); } } catch (e) { console.error(e); return done(e); } } ));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => { try { const r = await pool.query('SELECT id, username FROM users WHERE id = $1', [id]); if (r.rows.length > 0) { done(null, r.rows[0]); } else { done(null, false); } } catch (e) { console.error(e); done(e); } });
const createTable = async () => { const uQ=`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`; const sQ=`CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default","sess" json NOT NULL,"expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE); DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_sessions_pkey') THEN ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE; END IF; END $$; CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON "user_sessions" ("expire");`; const cQ=` CREATE TABLE IF NOT EXISTS images ( id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, category_1 VARCHAR(100) DEFAULT 'default_cat1', category_2 VARCHAR(100) DEFAULT 'default_cat2', category_3 VARCHAR(100) DEFAULT 'default_cat3', folder_name VARCHAR(100) DEFAULT 'default_folder' );`; const aCs=[`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_1') THEN ALTER TABLE images ADD COLUMN category_1 VARCHAR(100) DEFAULT 'default_cat1'; END IF; END $$;`,`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_2') THEN ALTER TABLE images ADD COLUMN category_2 VARCHAR(100) DEFAULT 'default_cat2'; END IF; END $$;`,`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='category_3') THEN ALTER TABLE images ADD COLUMN category_3 VARCHAR(100) DEFAULT 'default_cat3'; END IF; END $$;`,`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END $$;`]; try { await pool.query(uQ); await pool.query(sQ); await pool.query(cQ); for(const q of aCs){await pool.query(q);} console.log('DB tables ready.'); } catch(e){ console.error('DB init err:',e); } };

// --- R2接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({ region: 'auto', endpoint: r2Endpoint, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } });

// ▼▼▼ Multer (アップロード処理) 設定 (★元のファイル名で直接保存) ▼▼▼
const upload = multer({
    storage: multerS3({
        s3: s3Client,
        bucket: R2_BUCKET_NAME,
        acl: 'public-read',
        key: function (req, file, cb) {
            // ★ 元のファイル名をそのままキーとして使用
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
            console.log(`[Upload V3] Using original key: ${originalName}`);
            cb(null, originalName); // 元のファイル名でアップロード
        },
        contentType: multerS3.AUTO_CONTENT_TYPE
    }),
    fileFilter: (req, file, cb) => { if (file.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});
// ▲▲▲ Multer ここまで ▲▲▲

// --- ログインチェック関数 ---
function isAuthenticated(req, res, next) { if (req.isAuthenticated()) { return next(); } res.redirect('/login'); }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要・ログイン必須の基本ルート (変更なし) ---
app.get('/login', (req, res) => { res.render('login.html', { messages: req.flash('error') }); });
app.post('/login', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login', failureFlash: true }));
app.get('/logout', (req, res, next) => { req.logout((err) => { if (err) { return next(err); } res.redirect('/login'); }); });
app.get('/', isAuthenticated, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ▼▼▼ アップロードAPI (/upload) (★元のファイル名でそのまま保存) ▼▼▼
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }

    console.log(`[Upload V3] Received ${req.files.length} files for ${category1}/${category2}/${category3}/${folderName}`);

    const cat1Trimmed = category1.trim();
    const cat2Trimmed = category2.trim();
    const cat3Trimmed = category3.trim();
    const folderNameTrimmed = folderName.trim();
    
    try {
        const insertPromises = [];
        for (const file of req.files) {
            // ★ file.key は Multer で設定した「元のファイル名」
            const targetFilename = file.key; 
            // ★ file.location は multer-s3 が R2 から返す完全なURL
            const targetUrl = file.location; 

            console.log(`[Upload V3] Saving to DB: ${targetFilename}`);

            // ★ DBに最終ファイル名で保存
            // (もし同じファイル名がDBにあっても、重複挿入されます。R2上は上書きされます)
            insertPromises.push(pool.query(
                `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [targetFilename, targetUrl, cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed]
            ));
        }
        
        await Promise.all(insertPromises);

        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${req.files.length} 件を元のファイル名で保存しました。` });

    } catch (error) {
        console.error('[Upload V3] Error during processing:', error);
        res.status(500).json({ message: 'ファイル処理エラー' });
    }
});
// ▲▲▲ アップロードAPI ここまで ▲▲▲

// CSV API (/download-csv) (変更なし)
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (前のコードと同じ) ... */ });
// --- ギャラリー用API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });
// --- カテゴリ・フォルダ編集API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
// --- カテゴリ・フォルダ削除API (変更なし) ---
async function performDelete(res, conditions, params, itemDescription) { /* ... */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { /* ... */ });
// --- 画像移動API (変更なし) ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* ... */ });
// --- 解析API (Tesseract.js 版) (変更なし) ---
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => { /* ... */ });


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// --- 省略した関数の補足 ---
// (省略部分は、前の回答 (10:48) の完全なコードからコピーしてください)