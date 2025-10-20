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

// --- Multer (一時ファイル名でアップロード - 変更なし) ---
const upload = multer({
    storage: multerS3({ s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read', key: (req, f, cb)=>{ const u=`temp_${Date.now()}_${Math.round(Math.random()*1E9)}${path.extname(f.originalname)}`; console.log(`Temp key: ${u}`); cb(null, u); }, contentType: multerS3.AUTO_CONTENT_TYPE }),
    fileFilter: (req, f, cb) => { if (f.mimetype.startsWith('image/')) { cb(null, true); } else { cb(new Error('画像のみ'), false); } }
});

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

// ▼▼▼ アップロードAPI (/upload) (★元のファイル名維持＋連番ロジックに変更) ▼▼▼
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body; // フォルダ名はここではベース名として使わない
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }
    console.log(`[Upload V2] Received ${req.files.length} files for ${category1}/${category2}/${category3}/${folderName}`);

    const cat1Trimmed = category1.trim();
    const cat2Trimmed = category2.trim();
    const cat3Trimmed = category3.trim();
    const folderNameTrimmed = folderName.trim();
    const processedFiles = [];

    try {
        // --- 連番計算用のヘルパー関数 ---
        const getNextSequenceNumber = async (baseName, ext) => {
            let highestNumber = 0;
            const likePattern = `${baseName}-%.${ext.substring(1)}`; // 例: card_A-%.png
            const countQuery = `
                SELECT title FROM images
                WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 AND folder_name = $4
                AND title LIKE $5
                ORDER BY title DESC LIMIT 1`;
             // ★ フォルダ名だけでなく、カテゴリも条件に加える
            const countResult = await pool.query(countQuery, [cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed, likePattern]);

            if (countResult.rows.length > 0) {
                const lastTitle = countResult.rows[0].title;
                const match = lastTitle.match(/-(\d+)\.[^.]+$/);
                if (match && match[1]) {
                    highestNumber = parseInt(match[1], 10);
                }
            }
            console.log(`[Upload V2] Found highest number: ${highestNumber} for base: ${baseName}, ext: ${ext}`);
            return highestNumber + 1;
        };

        // --- 各ファイルを処理 ---
        for (const file of req.files) {
            const tempKey = file.key; // 一時ファイル名 (例: temp_123.jpg)
            const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8'); // 元のファイル名
            const extension = path.extname(originalName).toLowerCase(); // 拡張子 (小文字)
            const baseNameOriginal = path.basename(originalName, extension); // 拡張子なしの元の名前

            let targetFilename; // 最終的なファイル名
            let targetKey;      // R2上のキー (パス)
            let targetUrl;

            // ★ 元のファイル名が "-数字" で終わるかチェック
            const numberMatch = baseNameOriginal.match(/^(.*)-(\d+)$/);

            if (numberMatch) {
                // "-数字" で終わる場合 -> 元のファイル名をそのまま使う
                targetFilename = originalName;
                console.log(`[Upload V2] Using original filename with number: ${targetFilename}`);
            } else {
                // "-数字" で終わらない場合 -> 新しく連番を計算して付与
                const baseNameForSeq = baseNameOriginal; // 元の名前をベースにする
                const nextNumber = await getNextSequenceNumber(baseNameForSeq, extension);
                targetFilename = `${baseNameForSeq}-${nextNumber}${extension}`;
                console.log(`[Upload V2] Calculated sequential filename: ${targetFilename}`);
            }

            targetKey = targetFilename; // R2上のキーも最終ファイル名と同じにする
            targetUrl = `${r2PublicUrl}/${encodeURIComponent(targetKey)}`;

            // ★ R2上でリネーム (コピー&削除)
            console.log(`[Upload V2] Renaming ${tempKey} to ${targetKey}`);
            const copyCommand = new CopyObjectCommand({ Bucket: R2_BUCKET_NAME, CopySource: `${R2_BUCKET_NAME}/${tempKey}`, Key: targetKey, ACL: 'public-read' });
            await s3Client.send(copyCommand);
            const deleteCommand = new S3DeleteObjectCommand({ Bucket: R2_BUCKET_NAME, Key: tempKey });
            await s3Client.send(deleteCommand);

            // ★ DBに最終ファイル名で保存
            await pool.query(
                `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [targetFilename, targetUrl, cat1Trimmed, cat2Trimmed, cat3Trimmed, folderNameTrimmed]
            );

            processedFiles.push(targetFilename);
            console.log(`[Upload V2] Saved ${targetFilename}`);
        }

        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${processedFiles.length} 件保存しました (ファイル名維持/連番)。` });

    } catch (error) {
        console.error('[Upload V2] Error during processing:', error);
        // ★ エラー時に一時ファイルを削除する処理を追加 (ベストエフォート)
        try {
            const tempFilesToDelete = req.files.map(f => ({ Key: f.key }));
            if (tempFilesToDelete.length > 0) {
                 const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: tempFilesToDelete } });
                 await s3Client.send(deleteCommand);
                 console.log(`[Upload V2] Cleaned up ${tempFilesToDelete.length} temp files after error.`);
            }
        } catch (cleanupError) {
             console.error('[Upload V2] Error during temp file cleanup:', cleanupError);
        }
        res.status(500).json({ message: 'ファイル処理エラー' });
    }
});
// ▲▲▲ アップロードAPI ここまで ▲▲▲

// CSV API (/download-csv) (変更なし)
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... */ });
// --- ギャラリー用API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
/* ... ( /api/cat2, /api/cat3, /api/folders, /api/images, /api/search ) ... */
// --- カテゴリ・フォルダ編集API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (PUT /api/cat2, /api/cat3, /api/folder) ... */
async function performDelete(res, conditions, params, itemDescription) { /* ... */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (DELETE /api/cat2, /api/cat3, /api/folder) ... */
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
// pool, session, passport use/serialize/deserialize, createTable, s3Client, upload(一部), isAuthenticated
// 基本的なAPI (/login, /logout, /, /download-csv, /api/cat*, /api/folders*, /api/images*, /api/search, PUT/DELETE /api/*)
// の基本ロジックは前のコードと同じ