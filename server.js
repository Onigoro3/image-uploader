// ステップ4Aで入れた部品を読み込む
require('dotenv').config(); // .env ファイルを最初に読み込む
const express = require('express');
const multer = require('multer');
const multerS3 = require('multer-s3'); // ローカル保存の代わりにS3/R2を使う
const { S3Client } = require('@aws-sdk/client-s3'); // R2接続クライアント
const { Pool } = require('pg'); // データベース接続クライアント
const path = require('path');

const app = express();
const port = process.env.PORT || 3000; // Renderが指定するPORTに対応

// --- 1. データベース (PostgreSQL) 接続設定 ---
// .env の DATABASE_URL を読み込んで接続
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Render DB への接続に必要
    }
});

// ★ データベースにテーブルを作成する関数 (初回起動時に実行)
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

// --- 2. ストレージ (Cloudflare R2) 接続設定 ---
// .env の R2 情報を読み込む
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;

const s3Client = new S3Client({
    region: 'auto', // R2は 'auto'
    endpoint: r2Endpoint,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// --- 3. Multer (アップロード処理) の設定 ---
// diskStorage (ローカル保存) の代わりに multerS3 (R2保存) を使う
const upload = multer({
    storage: multerS3({
        s3: s3Client,
        bucket: process.env.R2_BUCKET_NAME,
        acl: 'public-read', // R2側でパブリック設定済みなら念のため
        metadata: function (req, file, cb) {
            cb(null, { fieldName: file.fieldname });
        },
        key: function (req, file, cb) {
            // ファイル名をそのまま保存 (日本語対応)
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

// --- サーバーの処理 ---

// 1. ルート ('/') で index.html を表示
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. 一括アップロード（/upload）の処理
app.post('/upload', upload.array('imageFiles', 100), async (req, res) => {
    
    if (req.files && req.files.length > 0) {
        try {
            // ★ uploadHistory 配列の代わりに、DBにINSERTする
            const insertPromises = req.files.map(file => {
                // R2の公開URL (r2PublicUrl) とファイル名を組み合わせる
                // file.key は multerS3 で設定した日本語ファイル名
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`; 
                const title = file.key;
                
                return pool.query(
                    'INSERT INTO images (title, url) VALUES ($1, $2)',
                    [title, fileUrl]
                );
            });
            
            await Promise.all(insertPromises); // 全てのDB書き込みが完了するまで待つ

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
}, (error, req, res, next) => {
    res.status(400).json({ message: error.message });
});

// 3. CSVダウンロード（/download-csv）の処理
app.get('/download-csv', async (req, res) => {
    try {
        // ★ uploadHistory 配列の代わりに、DBからSELECTする
        const { rows } = await pool.query('SELECT title, url FROM images ORDER BY created_at DESC');

        if (rows.length === 0) {
            res.status(404).send('アップロード履歴がまだありません。');
            return;
        }

        let csvContent = ",題名,URL\n"; // A列は空欄
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

// --- サーバーの起動 ---
app.listen(port, async () => {
    // 起動時にDBテーブルが存在するか確認・作成する
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});