// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// --- 1. データベース (PostgreSQL) 接続 ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// DBテーブル作成関数 (変更なし)
const createTable = async () => {
    const queryText = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`;
    try {
        await pool.query(queryText);
        console.log('Database table "images" is ready.');
    } catch (err) {
        console.error('Failed to create database table:', err);
    }
};

// --- 2. ストレージ (Cloudflare R2) 接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;

const s3Client = new S3Client({
    region: 'auto',
    endpoint: r2Endpoint,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// --- 3. Multer (アップロード処理) 設定 ---
const upload = multer({
    storage: multerS3({
        s3: s3Client,
        bucket: process.env.R2_BUCKET_NAME,
        acl: 'public-read',
        key: function (req, file, cb) {
            const decodedFilename = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, decodedFilename);
        }
    }),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('画像ファイルのみアップロード可能です。'), false);
        }
    }
});

// --- サーバーの処理 (ここからが本番) ---

// 1. ルート ('/') で index.html を表示 (変更なし)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. 一括アップロード（/upload）の処理 (変更なし)
app.post('/upload', upload.array('imageFiles', 100), async (req, res) => {
    if (req.files && req.files.length > 0) {
        try {
            const insertPromises = req.files.map(file => {
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`;
                const title = file.key;
                return pool.query(
                    'INSERT INTO images (title, url) VALUES ($1, $2)',
                    [title, fileUrl]
                );
            });
            await Promise.all(insertPromises);
            res.json({ 
                message: `${req.files.length} 件の画像をアップロードしました。`,
                count: req.files.length
            });
        } catch (dbError) {
            console.error('Database insert error:', dbError);
            res.status(500).json({ message: 'データベースへの保存に失敗しました。' });
        }
    } else {
        res.status(400).json({ message: 'アップロードするファイルが選択されていません。' });
    }
});

// 3. CSVダウンロード（/download-csv）の処理 (変更なし)
app.get('/download-csv', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT title, url FROM images ORDER BY created_at DESC');
        if (rows.length === 0) {
            res.status(404).send('アップロード履歴がまだありません。');
            return;
        }
        let csvContent = ",題名,URL\n";
        rows.forEach(item => {
            const title = `"${item.title.replace(/"/g, '""')}"`;
            const url = `"${item.url.replace(/"/g, '""')}"`;
            csvContent += `,${title},${url}\n`;
        });
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="upload_list.csv"');
        res.status(200).send(bom + csvContent);
    } catch (dbError) {
        console.error('Database select error:', dbError);
        res.status(500).send('データベースからの読み込みに失敗しました。');
    }
});

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 4. 【新機能】 日付リスト取得API (/api/dates)
// データベースを調べて、画像がアップロードされた日付（重複なし）を返します
app.get('/api/dates', async (req, res) => {
    try {
        // created_at (タイムスタンプ) を 'YYYY-MM-DD' 形式の「日付」に変換し、
        // 重複を削除(DISTINCT)して、新しい順(DESC)に並べ替えます
        const queryText = `
            SELECT DISTINCT DATE(created_at) AS upload_date 
            FROM images 
            ORDER BY upload_date DESC
        `;
        const { rows } = await pool.query(queryText);
        
        // { upload_date: '2025-10-19' } のようなオブジェクトの配列を
        // '2025-10-19' のような文字列の配列に変換します
        const dates = rows.map(row => row.upload_date);
        
        res.json(dates); // JSON形式で日付の配列を返す
        
    } catch (dbError) {
        console.error('API /api/dates error:', dbError);
        res.status(500).json({ message: '日付の読み込みに失敗しました。' });
    }
});

// 5. 【新機能】 特定の日付の画像リスト取得API (/api/images/:date)
// '2025-10-19' のような日付を受け取ったら、その日にアップロードされた画像の
// 「題名」と「URL」のリストを返します
app.get('/api/images/:date', async (req, res) => {
    try {
        const { date } = req.params; // URLから :date の部分 (例: '2025-10-19') を受け取る
        
        // $1 というプレースホルダーに、受け取った日付(date)を安全に挿入します
        const queryText = `
            SELECT title, url 
            FROM images 
            WHERE DATE(created_at) = $1 
            ORDER BY created_at DESC
        `;
        const { rows } = await pool.query(queryText, [date]);
        
        res.json(rows); // JSON形式で画像の配列を返す
        
    } catch (dbError) {
        console.error('API /api/images/:date error:', dbError);
        res.status(500).json({ message: '画像の読み込みに失敗しました。' });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});