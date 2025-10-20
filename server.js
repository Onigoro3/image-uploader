// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
// ▼▼▼ R2/S3のコピー・削除コマンドを追加 ▼▼▼
const { S3Client, DeleteObjectsCommand, CopyObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
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
const createTable = async () => { const uQ=`...`; const sQ=`...`; const cQ=`...`; const aCs=[`...`,`...`,`...`,`...`]; try { await pool.query(uQ); await pool.query(sQ); await pool.query(cQ); for(const q of aCs){await pool.query(q);} console.log('DB tables ready.'); } catch(e){ console.error('DB init err:',e); } }; // (DBスキーマは変更なし)

// --- R2接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
});

// ▼▼▼ Multer (アップロード処理) 設定 (★一時ファイル名生成に変更) ▼▼▼
const upload = multer({
    storage: multerS3({
        s3: s3Client,
        bucket: R2_BUCKET_NAME,
        acl: 'public-read',
        key: function (req, file, cb) {
            // ★ 一時的なユニークファイル名を生成 (例: temp_1678886400000_random.jpg)
            const uniqueSuffix = Date.now() + '_' + Math.round(Math.random() * 1E9);
            const extension = path.extname(file.originalname);
            const tempFilename = `temp_${uniqueSuffix}${extension}`;
            console.log(`[Upload] Generating temp key: ${tempFilename}`);
            cb(null, tempFilename); // 一時ファイル名でアップロード
        },
        contentType: multerS3.AUTO_CONTENT_TYPE // ★ コンテンツタイプを自動設定
    }),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) { cb(null, true); }
        else { cb(new Error('画像のみ'), false); }
    }
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

// ▼▼▼ アップロードAPI (/upload) (★連番リネーム処理を追加) ▼▼▼
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    const { category1, category2, category3, folderName } = req.body;
    if (!category1 || !category2 || !category3 || !folderName ) { return res.status(400).json({ message: '全カテゴリ・フォルダ名必須' }); }
    if (!req.files || req.files.length === 0) { return res.status(400).json({ message: 'ファイル未選択' }); }

    console.log(`[Upload] Received ${req.files.length} files for ${category1}/${category2}/${category3}/${folderName}`);

    // ★ ベースとなるファイル名を決定 (ここではフォルダ名を使用)
    const baseName = folderName.trim();
    let highestNumber = 0;

    try {
        // 1. ★ 現在のフォルダ内の最大連番を取得 (例: 'folder-3.jpg' -> 3)
        const countQuery = `
            SELECT title FROM images
            WHERE category_1 = $1 AND category_2 = $2 AND category_3 = $3 AND folder_name = $4
            ORDER BY title DESC LIMIT 1`;
        const countResult = await pool.query(countQuery, [category1.trim(), category2.trim(), category3.trim(), baseName]);

        if (countResult.rows.length > 0) {
            const lastTitle = countResult.rows[0].title;
            // ファイル名から最後の数字を抽出 (例: 'abc-123.jpg' -> 123)
            const match = lastTitle.match(/-(\d+)\.[^.]+$/);
            if (match && match[1]) {
                highestNumber = parseInt(match[1], 10);
                console.log(`[Upload] Found highest number: ${highestNumber} for base: ${baseName}`);
            }
        }

        let nextNumber = highestNumber + 1;
        const processedFiles = []; // 正常に処理されたファイル情報

        // 2. ★ アップロードされた各ファイルを処理 (R2リネーム + DB保存)
        for (const file of req.files) {
            const tempKey = file.key; // MulterがR2に保存した一時ファイル名 (例: temp_123.jpg)
            const extension = path.extname(tempKey);
            const newFilename = `${baseName}-${nextNumber}${extension}`; // 新しい連番ファイル名 (例: folder-5.jpg)
            const newKey = newFilename; // R2上のキー（ファイルパス）も同じにする
            const newUrl = `${r2PublicUrl}/${encodeURIComponent(newKey)}`;

            console.log(`[Upload] Renaming ${tempKey} to ${newKey}`);

            // 3. ★ R2上でファイルをコピー (一時名 -> 新しい連番名)
            const copyCommand = new CopyObjectCommand({
                Bucket: R2_BUCKET_NAME,
                CopySource: `${R2_BUCKET_NAME}/${tempKey}`, // コピー元
                Key: newKey, // コピー先
                ACL: 'public-read' // コピー後も公開設定を維持
            });
            await s3Client.send(copyCommand);

            // 4. ★ R2上の一時ファイルを削除
            const deleteCommand = new DeleteObjectCommand({
                Bucket: R2_BUCKET_NAME,
                Key: tempKey,
            });
            await s3Client.send(deleteCommand);

            // 5. ★ 新しいファイル名でデータベースに保存
            await pool.query(
                `INSERT INTO images (title, url, category_1, category_2, category_3, folder_name)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [newFilename, newUrl, category1.trim(), category2.trim(), category3.trim(), folderName.trim()]
            );

            processedFiles.push(newFilename); // 成功リストに追加
            nextNumber++; // 次のファイルの番号へ
            console.log(`[Upload] Successfully processed and saved ${newFilename}`);
        }

        res.json({ message: `「${category1}/${category2}/${category3}/${folderName}」に ${processedFiles.length} 件を連番で保存しました。` });

    } catch (error) {
        console.error('[Upload] Error during file processing or renaming:', error);
        // ★ エラーが発生した場合、中途半端に作られたR2ファイルなどを削除する処理が必要になる場合がある (今回は省略)
        res.status(500).json({ message: 'ファイルの処理中にエラーが発生しました。' });
    }
});
// ▲▲▲ アップロードAPI ここまで ▲▲▲

// CSV API (/download-csv) (変更なし)
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (前のコードと同じ - 拡張子削除済み) ... */ });
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