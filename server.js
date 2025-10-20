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
const { createWorker } = require('tesseract.js'); // OCR
const sharp = require('sharp'); // ★ 画像処理
const https = require('https'); // ★ 画像URLからデータを取得するため

const app = express();
const port = process.env.PORT || 3000;

// --- DB接続, Middleware, Passport, DBテーブル作成 (変更なし) ---
const pool = new Pool({ /* ... */ });
app.engine('html', ejs.renderFile); /* ... */ app.use(express.json()); /* ... */ app.use(session({ /* ... */ })); /* ... */
passport.use(new LocalStrategy( /* ... */ )); /* ... */
const createTable = async () => { /* ... */ }; // 変更なし (4階層のまま)

// --- R2接続, Multer設定 (変更なし) ---
const r2Endpoint = /* ... */; const r2PublicUrl = /* ... */; const R2_BUCKET_NAME = /* ... */; const s3Client = new S3Client({ /* ... */ });
const upload = multer({ /* ... */ });

// --- ログインチェック関数 (変更なし) ---
function isAuthenticated(req, res, next) { /* ... */ }

// -----------------------------------------------------------------
// ★★★★★ ルート（URL）設定 ★★★★★
// -----------------------------------------------------------------

// --- 認証不要・ログイン必須の基本ルート (変更なし) ---
app.get('/login', /* ... */ ); app.post('/login', /* ... */ ); app.get('/logout', /* ... */ );
app.get('/', isAuthenticated, /* ... */ );
app.post('/upload', isAuthenticated, upload.array('imageFiles', 100), async (req, res) => { /* ... (4階層保存) ... */ });
app.get('/download-csv', isAuthenticated, async (req, res) => { /* ... (フォルダ指定CSV, 4階層出力) ... */ });
// --- ギャラリー用API (変更なし) ---
app.get('/api/cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat2/:cat1', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/cat3/:cat1/:cat2', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/folders/:cat1/:cat2/:cat3', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/images/:folderName', isAuthenticated, async (req, res) => { /* ... */ });
app.get('/api/search', isAuthenticated, async (req, res) => { /* ... */ });
// --- カテゴリ・フォルダ編集・削除API (変更なし) ---
app.put('/api/cat1/:oldName', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (PUT /api/cat2, /api/cat3, /api/folder) ... */
async function performDelete(res, conditions, params, itemDescription) { /* ... */ }
app.delete('/api/cat1/:name', isAuthenticated, async (req, res) => { /* ... */ }); /* ... (DELETE /api/cat2, /api/cat3, /api/folder) ... */
// --- 画像移動API (変更なし) ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* ... */ });


// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 13. 【★全面改修★】 フォルダ解析API (/api/analyze/:folderName) (領域別OCR)
app.post('/api/analyze/:folderName', isAuthenticated, async (req, res) => {
    const { folderName } = req.params;
    console.log(`[Analyze V2] Req: ${folderName}`);
    let worker;

    // --- ★ 画像URLからBufferを取得するヘルパー関数 ---
    const getImageBuffer = (url) => new Promise((resolve, reject) => {
        https.get(url, (response) => {
            if (response.statusCode !== 200) {
                return reject(new Error(`Failed to get image: ${response.statusCode}`));
            }
            const data = [];
            response.on('data', (chunk) => data.push(chunk));
            response.on('end', () => resolve(Buffer.concat(data)));
        }).on('error', (err) => reject(err));
    });

    // --- ★ OCR実行ヘルパー関数 (sharpで前処理を追加) ---
    const runOCR = async (buffer, regionName) => {
        try {
            // 前処理: グレースケール化、コントラスト調整、必要なら二値化 (Tesseractは内部である程度行う)
            const processedBuffer = await sharp(buffer)
                .grayscale()
                // .linear(1.5, -128) // コントラスト強調 (調整が必要)
                // .threshold(128) // 二値化 (閾値調整が必要)
                .toBuffer();
            const { data: { text } } = await worker.recognize(processedBuffer);
            console.log(`[Analyze V2] OCR Success [${regionName}]`);
            return text.replace(/"/g, '""').replace(/\n/g, ' ').trim(); // CSV用に整形
        } catch (ocrError) {
            console.error(`[Analyze V2] OCR Error [${regionName}]:`, ocrError.message);
            return '*** OCRエラー ***';
        }
    };

    try {
        // 1. 対象画像のURLリスト取得 (変更なし)
        const { rows } = await pool.query('SELECT title, url FROM images WHERE folder_name = $1 ORDER BY title', [folderName]);
        if (rows.length === 0) return res.status(404).json({ message: '画像なし' });
        console.log(`[Analyze V2] Found ${rows.length} images`);

        // 2. Tesseract Worker 初期化 (変更なし)
        worker = await createWorker('jpn+eng', 1, { logger: m => console.log(`[Tesseract] ${m.status}: ${m.progress * 100}%`) });
        console.log('[Analyze V2] Worker init.');

        let analysisResults = []; // { filename, cardName, cardText, power, cost, expansion }

        // 3. ★ 各画像を処理 (sharpで領域分割 + OCR)
        for (const image of rows) {
            console.log(`[Analyze V2] Processing: ${image.title}`);
            const result = { filename: image.title, cardName: '', cardText: '', power: '', cost: '', expansion: '' };
            try {
                const imageBuffer = await getImageBuffer(image.url);
                const metadata = await sharp(imageBuffer).metadata();
                const width = metadata.width;
                const height = metadata.height;

                // ★★★ 領域定義 (カードサイズやレイアウトに合わせて要調整！) ★★★
                // (左上隅が (0,0)。値は%ではなくピクセル。)
                const regions = {
                    // デュエマカード画像 (DM-25EX2-DMR1.jpg) を元に推測
                    cardName: { left: Math.round(width * 0.1), top: Math.round(height * 0.05), width: Math.round(width * 0.8), height: Math.round(height * 0.08) },
                    cost:     { left: Math.round(width * 0.03), top: Math.round(height * 0.03), width: Math.round(width * 0.1), height: Math.round(height * 0.08) },
                    cardText: { left: Math.round(width * 0.1), top: Math.round(height * 0.55), width: Math.round(width * 0.8), height: Math.round(height * 0.3) },
                    power:    { left: Math.round(width * 0.05), top: Math.round(height * 0.88), width: Math.round(width * 0.25), height: Math.round(height * 0.08) },
                    expansion:{ left: Math.round(width * 0.65), top: Math.round(height * 0.88), width: Math.round(width * 0.25), height: Math.round(height * 0.05) },
                    // 他にも種族(type)などの領域を追加可能
                };

                // 各領域を切り出してOCR
                if (regions.cardName) result.cardName = await runOCR(await sharp(imageBuffer).extract(regions.cardName).toBuffer(), 'Name');
                if (regions.cost)     result.cost = await runOCR(await sharp(imageBuffer).extract(regions.cost).toBuffer(), 'Cost');
                if (regions.cardText) result.cardText = await runOCR(await sharp(imageBuffer).extract(regions.cardText).toBuffer(), 'Text');
                if (regions.power)    result.power = await runOCR(await sharp(imageBuffer).extract(regions.power).toBuffer(), 'Power');
                if (regions.expansion) result.expansion = await runOCR(await sharp(imageBuffer).extract(regions.expansion).toBuffer(), 'Expansion');

                analysisResults.push(result);
                console.log(`[Analyze V2] Processed ${image.title}`);

            } catch (imgError) {
                console.error(`[Analyze V2] Image Processing Error for ${image.title}:`, imgError.message);
                analysisResults.push({ ...result, cardName: '*** 画像処理エラー ***' }); // エラーも記録
            }
        }

        // 4. Worker終了 (変更なし)
        await worker.terminate(); worker = null; console.log('[Analyze V2] Worker terminated.');

        // 5. ★ 結果をCSV形式で生成 (複数列)
        let csvContent = "ファイル名,カード名,コスト,テキスト,パワー,エキスパンション\n"; // ヘッダー
        analysisResults.forEach(r => {
            csvContent += `"${r.filename}","${r.cardName}","${r.cost}","${r.cardText}","${r.power}","${r.expansion}"\n`;
        });

        // 6. CSVダウンロード (変更なし)
        const fileName = `analysis_detailed_${folderName}.csv`;
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
        res.status(200).send(bom + csvContent);
        console.log(`[Analyze V2] Sent detailed CSV`);

    } catch (error) {
        console.error(`[Analyze V2] Error:`, error);
        if (worker) { try { await worker.terminate(); } catch (e) { console.error('Error terminating worker:', e);} }
        res.status(500).json({ message: '解析エラー発生' });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- 画像移動API (/api/image/:imageTitle) (変更なし) ---
app.put('/api/image/:imageTitle', isAuthenticated, async (req, res) => { /* ... */ });

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable();
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});

// --- 省略した関数の補足 ---
// pool, session, passport use/serialize/deserialize, createTable, s3Client, upload, isAuthenticated
// 基本的なAPI (/login, /logout, /, /upload, /download-csv(通常版), /api/cat*, /api/folders*, /api/images*, /api/search, PUT/DELETE /api/*)
// の基本ロジックは前のコードと同じ