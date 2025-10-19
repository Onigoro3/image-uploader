// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const path = require('path');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const PgSession = require('connect-pg-simple')(session);
const flash = require('connect-flash');
const ejs = require('ejs');

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({ /* ... (変更なし) ... */ });

// --- Middleware 設定 (変更なし) ---
app.engine('html', ejs.renderFile); app.set('view engine', 'html'); app.set('views', __dirname);
app.use(express.json()); app.use(express.urlencoded({ extended: false }));
app.use(session({ /* ... (変更なし) ... */ }));
app.use(flash()); app.use(passport.initialize()); app.use(passport.session());

// --- Passport 設定 (変更なし) ---
passport.use(new LocalStrategy( /* ... (変更なし) ... */ ));
passport.serializeUser((user, done) => { /* ... (変更なし) ... */ });
passport.deserializeUser(async (id, done) => { /* ... (変更なし) ... */ });

// --- DBテーブル自動作成関数 (変更なし - 前回で4階層対応済み) ---
const createTable = async () => { /* ... (変更なし) ... */ };

// --- ストレージ (R2) 接続 (変更なし) ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;
const s3Client = new S3Client({ /* ... (変更なし) ... */ });

// --- Multer (アップロード処理) 設定 (変更なし) ---
const upload = multer({ /* ... (変更なし) ... */ });

// --- ログインチェック関数 (変更なし) ---
function isAuthenticated(req, res, next) { /* ... (変更なし) ... */ }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要ルート (変更なし) ---
app.get('/login', (req, res) => { /* ... */ });
app.post('/login', passport.authenticate('local', { /* ... */ }));
app.get('/logout', (req, res, next) => { /* ... */ });

// --- ログイン必須ルート ---

app.get('/', isAuthenticated, (req, res) => { /* ... (変更なし) ... */ });
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* ... (変更なし - 4階層保存) ... */ });
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (変更なし - フォルダ指定CSV) ... */ });

// --- ギャラリー用API (変更なし - 前回で4階層対応済み) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// --- ★【新機能】カテゴリ・フォルダの編集・削除API ---

// --- 名前変更 (Rename) API ---
// (PUT /api/cat1/:oldName)
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => {
    const { oldName } = req.params;
    const { newName } = req.body; // ★ JS側は newName で送る
    if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'});
    try {
        await pool.query('UPDATE images SET category_1 = $1 WHERE category_1 = $2', [newName.trim(), oldName]);
        res.json({ message: `大カテゴリ名を「${oldName}」から「${newName}」に変更しました。` });
    } catch (error) { console.error("Rename Cat1 Error:", error); res.status(500).json({ message: '名前変更失敗' }); }
});
// (PUT /api/cat2/:cat1/:oldName)
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => {
    const { cat1, oldName } = req.params;
    const { newName } = req.body;
     if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'});
    try {
        // 特定の cat1 の下にある cat2 の名前だけを変更
        await pool.query('UPDATE images SET category_2 = $1 WHERE category_1 = $2 AND category_2 = $3', [newName.trim(), cat1, oldName]);
         res.json({ message: `中カテゴリ名を「${oldName}」から「${newName}」に変更しました。` });
    } catch (error) { console.error("Rename Cat2 Error:", error); res.status(500).json({ message: '名前変更失敗' }); }
});
// (PUT /api/cat3/:cat1/:cat2/:oldName)
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => {
    const { cat1, cat2, oldName } = req.params;
    const { newName } = req.body;
     if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'});
    try {
        await pool.query('UPDATE images SET category_3 = $1 WHERE category_1 = $2 AND category_2 = $3 AND category_3 = $4', [newName.trim(), cat1, cat2, oldName]);
         res.json({ message: `小カテゴリ名を「${oldName}」から「${newName}」に変更しました。` });
    } catch (error) { console.error("Rename Cat3 Error:", error); res.status(500).json({ message: '名前変更失敗' }); }
});
// (PUT /api/folder/:oldName) - ★APIパスを簡略化 (JS側も修正必要) / 階層情報は不要
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { // ★パス変更
    const { oldName } = req.params;
    const { newName } = req.body; // ★ JS側は newName で送る
     if (!newName || newName.trim() === '' || newName.trim() === oldName) return res.status(400).json({message: 'Invalid name'});
    try {
        // ★注意: 同じフォルダ名が別のカテゴリ階層に存在すると、それらも全て変更されます。
        //   もし階層ごとにユニークにしたい場合は、WHERE句に cat1, cat2, cat3 の条件を追加する必要があります。
        await pool.query('UPDATE images SET folder_name = $1 WHERE folder_name = $2', [newName.trim(), oldName]);
         res.json({ message: `フォルダ名を「${oldName}」から「${newName}」に変更しました。` });
    } catch (error) { console.error("Rename Folder Error:", error); res.status(500).json({ message: '名前変更失敗' }); }
});

// --- 削除 (Delete) API ---
// ★ 共通の削除処理関数
async function performDelete(res, conditions, params, itemDescription) {
    try {
        // 1. R2からファイルを削除するためにファイル名リストを取得
        const { rows } = await pool.query(`SELECT title FROM images WHERE ${conditions}`, params);
        if (rows.length > 0) {
            const objectsToDelete = rows.map(row => ({ Key: row.title }));
            const deleteCommand = new DeleteObjectsCommand({ Bucket: R2_BUCKET_NAME, Delete: { Objects: objectsToDelete } });
            await s3Client.send(deleteCommand);
            console.log(`Deleted ${objectsToDelete.length} objects from R2 for ${itemDescription}`);
        }
        // 2. DBから履歴を削除
        await pool.query(`DELETE FROM images WHERE ${conditions}`, params);
        res.json({ message: `${itemDescription} を完全に削除しました。` });
    } catch (error) {
        console.error(`Delete ${itemDescription} Error:`, error);
        res.status(500).json({ message: '削除失敗' });
    }
}

// (DELETE /api/cat1/:name)
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, 'category_1 = $1', [req.params.name], `大カテゴリ「${req.params.name}」`);
});
// (DELETE /api/cat2/:cat1/:name)
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, 'category_1 = $1 AND category_2 = $2', [req.params.cat1, req.params.name], `中カテゴリ「${req.params.name}」`);
});
// (DELETE /api/cat3/:cat1/:cat2/:name)
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => {
    await performDelete(res, 'category_1 = $1 AND category_2 = $2 AND category_3 = $3', [req.params.cat1, req.params.cat2, req.params.name], `小カテゴリ「${req.params.name}」`);
});
// (DELETE /api/folder/:name) - ★パス変更
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => {
    // ★注意: 同じフォルダ名が別のカテゴリ階層に存在すると、それらも全て削除されます。
    await performDelete(res, 'folder_name = $1', [req.params.name], `フォルダ「${req.params.name}」`);
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});