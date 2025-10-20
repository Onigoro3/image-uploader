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
// ▼▼▼ OCRライブラリを追加 ▼▼▼
const { createWorker } = require('tesseract.js');
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 (変更なし) ---
const pool = new Pool({ /* ... */ });
// --- Middleware 設定 (変更なし) ---
app.engine('html', ejs.renderFile); /* ... */ app.use(express.json()); /* ... */ app.use(session({ /* ... */ })); /* ... */
// --- Passport 設定 (変更なし) ---
passport.use(new LocalStrategy( /* ... */ )); /* ... */
// --- DBテーブル自動作成関数 (変更なし) ---
const createTable = async () => { /* ... */ };
// --- ストレージ (R2) 接続 (変更なし) ---
const r2Endpoint = /* ... */; const r2PublicUrl = /* ... */; const R2_BUCKET_NAME = /* ... */; const s3Client = new S3Client({ /* ... */ });
// --- Multer (アップロード処理) 設定 (変更なし) ---
const upload = multer({ /* ... */ });
// --- ログインチェック関数 (変更なし) ---
function isAuthenticated(req, res, next) { /* ... */ }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要ルート (変更なし) ---
app.get('/login', /* ... */ ); app.post('/login', /* ... */ ); app.get('/logout', /* ... */ );

// --- ログイン必須ルート ---
app.get('/', isAuthenticated, /* ... */ );
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* ... (4階層保存 - 変更なし) ... */ });
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (フォルダ指定CSV - 変更なし) ... */ });
// --- ギャラリー用API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });
// --- カテゴリ・フォルダの編集・削除API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat2/:cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/cat3/:cat1/:cat2/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.put('/api/folder/:oldName', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/cat2/:cat1/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/cat3/:cat1/:cat2/:name', isAuthenticated, async (req, res) => { /* ... */ });
app.delete('/api/folder/:name', isAuthenticated, async (req, res) => { /* ... */ });

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 13. 【新機能】 フォルダ解析API (/api/analyze/:folderName)
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    console.log(`[Analyze] Received request for folder: ${folderName}`);
    let worker; // Workerをtryの外で宣言

    try {
        // 1. 対象画像のURLリストをDBから取得
        const { rows } = await pool.query('SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title', [folderName]);
        if (rows.length === 0) {
            return res.status(404).json({ message: '対象フォルダに画像がありません。' });
        }
        console.log(`[Analyze] Found ${rows.length} images for folder ${folderName}`);

        // 2. Tesseract Worker を初期化 (日本語と英語に対応)
        // (Render上で言語データのダウンロードが発生する可能性あり)
        worker = await createWorker('jpn+eng', 1, { // ★ 'jpn+eng' で日本語と英語
             logger: m => console.log(`[Tesseract] ${m.status}: ${m.progress * 100}%`), // 進捗ログ
             // cacheMethod: 'none' // Renderのディスクは一時的なのでキャッシュしない方が良いかも
        });
        console.log('[Analyze] Tesseract worker initialized.');

        // 3. 各画像を順番にOCR処理
        let analysisResults = [];
        for (const image of rows) {
            console.log(`[Analyze] Processing image: ${image.title} (${image.url})`);
            try {
                 const { data: { text } } = await worker.recognize(image.url);
                 analysisResults.push({
                     filename: image.title,
                     recognizedText: text.replace(/"/g, '""') // CSV用にダブルクォートをエスケープ
                 });
                 console.log(`[Analyze] OCR complete for ${image.title}`);
            } catch (ocrError) {
                 console.error(`[Analyze] OCR Error for ${image.title}:`, ocrError.message);
                 analysisResults.push({ filename: image.title, recognizedText: '*** OCRエラー ***' });
            }
        }

        // 4. Workerを終了
        await worker.terminate();
        console.log('[Analyze] Tesseract worker terminated.');
        worker = null; // 参照をクリア

        // 5. 結果をCSV形式で生成
        let csvContent = "ファイル名,認識されたテキスト\n"; // ヘッダー
        analysisResults.forEach(result => {
            csvContent += `"${result.filename}","${result.recognizedText}"\n`;
        });

        // 6. CSVファイルをダウンロードさせる
        const fileName = `analysis_${folderName}.csv`;
        const bom = '\uFEFF'; // BOM for Excel
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        // ★ ファイル名を正しくエンコードしてヘッダーに設定
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
        res.status(200).send(bom + csvContent);
        console.log(`[Analyze] Sent CSV for folder: ${folderName}`);

    } catch (error) {
        console.error(`[Analyze] Error analyzing folder ${folderName}:`, error);
        // Workerが起動中の場合、必ず終了させる
        if (worker) {
            try { await worker.terminate(); console.log('[Analyze] Terminated worker due to error.'); }
            catch (termError) { console.error('[Analyze] Error terminating worker:', termError); }
        }
        res.status(500).json({ message: 'フォルダの解析中にエラーが発生しました。' });
    }
});

// 14. 【新機能】 画像移動API (/api/image/:imageTitle)
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => {
    const { imageTitle } = req.params;
    // ★ 移動先のカテゴリ・フォルダ名をリクエストボディから取得
    const { category1, category2, category3, folderName } = req.body;

    if (!category1 || !category2 || !category3 || !folderName) {
        return res.status(400).json({ message: '移動先のカテゴリ・フォルダをすべて指定してください。' });
    }

    try {
        // ★ データベースの該当画像のレコードを更新
        const updateQuery = `
            UPDATE images
            SET category_1 = $1, category_2 = $2, category_3 = $3, folder_name = $4
            WHERE title = $5
        `;
        const result = await pool.query(updateQuery, [
            category1.trim(),
            category2.trim(),
            category3.trim(),
            folderName.trim(),
            imageTitle // 画像タイトルはURLデコード不要 (DBにそのまま保存されているはず)
        ]);

        if (result.rowCount === 0) {
            return res.status(404).json({ message: '対象の画像が見つかりませんでした。' });
        }

        console.log(`Moved image "${imageTitle}" to ${category1}/${category2}/${category3}/${folderName}`);
        res.json({ message: `画像を「${category1}/${category2}/${category3}/${folderName}」に移動しました。` });

    } catch (error) {
        console.error(`Failed to move image ${imageTitle}:`, error);
        res.status(500).json({ message: '画像の移動中にエラーが発生しました。' });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// --- 省略した関数の補足 ---
// pool, session, passport use/serialize/deserialize, createTable, s3Client, upload, isAuthenticated
// 各API (/login, /logout, /, /upload, /download-csv, /api/cat*, /api/folders*, /api/images*, /api/search, PUT/DELETE /api/*) の基本ロジックは前回と同じ