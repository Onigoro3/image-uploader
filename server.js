// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');

// ▼▼▼ 認証（ログイン）用の部品を読み込む ▼▼▼
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const PgSession = require('connect-pg-simple')(session); // セッションをDBに保存
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ▼▼▼ テンプレートエンジン(EJS) を使う設定（login.html の <% %> のため）▼▼▼
// （注：login.html の拡張子を .html のままにするための小細工）
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', __dirname); // .html ファイルは server.js と同じ階層にあると設定
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// ▼▼▼ サーバーが「フォーム送信」を読めるようにする設定 ▼▼▼
app.use(express.json()); // APIリクエスト用
app.use(express.urlencoded({ extended: false })); // ログインフォーム送信用
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// ▼▼▼ セッション管理（ログイン状態の維持）設定 ▼▼▼
app.use(session({
    store: new PgSession({ // セッションをPostgreSQLに保存
        pool: pool,                
        tableName: 'user_sessions' 
    }),
    secret: process.env.SESSION_SECRET || 'a_very_secret_key_that_should_be_in_env', // ★本当は.envに書くべき秘密鍵
    resave: false,
    saveUninitialized: false, // ログインするまでセッションを保存しない
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30日間有効
}));
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// ▼▼▼ Passport（認証）の初期設定 ▼▼▼
app.use(passport.initialize());
app.use(passport.session());

// Passport: ユーザー名を元にDBからユーザー情報を探すロジック
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (rows.length === 0) {
                return done(null, false, { message: 'ユーザー名が見つかりません。' });
            }
            const user = rows[0];
            // DBのハッシュ化されたパスワードと、入力されたパスワードを比較
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                return done(null, user); // ログイン成功
            } else {
                return done(null, false, { message: 'パスワードが間違っています。' });
            }
        } catch (err) {
            return done(err);
        }
    }
));

// Passport: ユーザー情報をセッションに保存するロジック
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Passport: セッションからユーザー情報を復元するロジック
passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, rows[0]);
    } catch (err) {
        done(err);
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- DBテーブル自動作成関数 (★`users` と `user_sessions` を追加) ---
const createTable = async () => {
    // ユーザーテーブル (パスワードをハッシュ化して保存)
    const userQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;
    // セッション保存用テーブル
    const sessionQuery = `
    CREATE TABLE IF NOT EXISTS "user_sessions" (
      "sid" varchar NOT NULL COLLATE "default",
      "sess" json NOT NULL,
      "expire" timestamp(6) NOT NULL
    ) WITH (OIDS=FALSE);
    ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
    CREATE INDEX "IDX_user_sessions_expire" ON "user_sessions" ("expire");
    `;
    // 既存のimagesテーブル改造クエリ
    const createQuery = `CREATE TABLE IF NOT EXISTS images ( ... );`; // (内容は前回と同じなので省略)
    const alterFolderQuery = `DO $$ ... $$;`; // (内容は前回と同じなので省略)
    const alterCategoryQuery = `DO $$ ... $$;`; // (内容は前回と同じなので省略)
    
    try {
        await pool.query(userQuery); // ★ユーザーテーブル作成
        await pool.query(sessionQuery); // ★セッションテーブル作成
        // await pool.query(createQuery); // (前回実行済みのはず)
        // await pool.query(alterFolderQuery); // (前回実行済みのはず)
        // await pool.query(alterCategoryQuery); // (前回実行済みのはず)
        
        console.log('Database tables (users, sessions, images) are ready.');
    } catch (err) {
        console.error('Failed to create/update database tables:', err);
    }
};
// (注: createQuery, alterFolderQuery, alterCategoryQuery の省略した部分は、
//   【フェーズ1】の server.js からコピーして貼り付けてください。
//   このコードは「認証」部分にフォーカスしています。)

// --- ストレージ (R2) 接続 (変更なし) ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME; 
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// --- Multer (アップロード処理) (変更なし) ---
const upload = multer({
    storage: multerS3({ ... }), // (内容は前回と同じなので省略)
    fileFilter: (req, file, cb) => { ... } // (内容は前回と同じなので省略)
});


// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証（ログイン）不要のルート ---

// 1. ログインページ (GET)
// ( /login にアクセスしたら、login.html を表示する)
app.get('/login', (req, res) => {
    // res.sendFile(path.join(__dirname, 'login.html')); // EJSを使うため変更
    res.render('login.html', { messages: req.flash('error') });
});

// 2. ログイン処理 (POST)
// ( login.html でフォームが送信されたら、Passportが認証する)
app.post('/login', passport.authenticate('local', {
    successRedirect: '/', // 成功したらメインページ '/' に飛ばす
    failureRedirect: '/login', // 失敗したら /login に戻す
    failureFlash: true // 失敗メッセージ(例: 'パスワードが違います') を /login に送る
}));

// 3. ログアウト処理 (GET)
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/login'); // ログアウトしたらログインページに戻す
    });
});


// --- ★★★ ここから下は、すべて「ログイン必須」のルート ★★★ ---

// 「ログインしていますか？」をチェックする"関所"
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { // Passport が「ログイン中」と判断したら
        return next(); // 次の処理（メインページやAPI）へ進む
    }
    // ログインしていなかったら、ログインページへ強制的に飛ばす
    res.redirect('/login');
}

// 4. メインページ ( / )
// ( / にアクセスしたら、まず isAuthenticated でチェックし、OKなら index.html を表示)
app.get('/', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 5. アップロードAPI (/upload) (★ isAuthenticated を追加)
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => {
    // (中身のロジックは前回と同じ)
    const { categoryName, folderName } = req.body; 
    // ... (以下、前回と同じコード)
});

// 6. フォルダ別CSV API (/download-csv) (★ isAuthenticated を追加)
app.get('/download-csv', isAuthenticated, async (req, res) => {
    // (中身のロジックは前回と同じ)
    const { folder } = req.query; 
    // ... (以下、前回と同じコード)
});

// 7. カテゴリリストAPI (/api/categories) (★ isAuthenticated を追加)
app.get('/api/categories', isAuthenticated, async (req, res) => {
    // (中身のロジックは前回と同じ)
    // ...
});

// 8. フォルダリストAPI (/api/folders_by_category/:categoryName) (★ isAuthenticated を追加)
app.get('/api/folders_by_category/:categoryName', isAuthenticated, async (req, res) => {
    // (中身のロジックは前回と同じ)
    // ...
});

// 9. 画像リストAPI (/api/images_by_folder/:folderName) (★ isAuthenticated を追加)
app.get('/api/images_by_folder/:folderName', isAuthenticated, async (req, res) => {
    // (中身のロジックは前回と同じ)
    // ...
});

// 10. フォルダ削除API (/api/folder/:folderName) (★ isAuthenticated を追加)
app.delete('/api/folder/:folderName', isAuthenticated, async (req, res) => {
    // (中身のロジックは前回と同じ)
    // ...
});


// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});