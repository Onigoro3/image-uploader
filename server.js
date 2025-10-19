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

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// ★ DBテーブル作成関数 (★自動でDBを改造する機能付き！)
const createTable = async () => {
    // 既存のテーブル作成クエリ
    const createQuery = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      folder_name VARCHAR(100) DEFAULT 'default'
    );`;

    // 既存のテーブルに `folder_name` カラムが「無い場合だけ」追加するクエリ
    const alterQuery = `
    DO $$
    BEGIN
        -- imagesテーブルにfolder_nameカラムが存在しないかチェック
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name='images' AND column_name='folder_name'
        ) THEN
            -- 存在しない場合のみ、カラムを追加する
            ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default';
        END IF;
    END;
    $$;`;
    
    try {
        await pool.query(createQuery); // テーブルがなければ作成
        await pool.query(alterQuery);  // ★★★ここで自動でカラムがなければ追加します★★★
        console.log('Database table "images" is ready with "folder_name" column.');
    } catch (err) {
        console.error('Failed to update database table:', err);
    }
};
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

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

// --- サーバーの処理 ---

// 1. ルート ('/') で index.html を表示 (変更なし)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 2. 一括アップロード（/upload）の処理 (「フォルダ名」を受け取るよう改造)
app.post('/upload', upload.array('imageFiles', 100), async (req, res) => {
    
    const { folderName } = req.body; 

    if (!folderName || folderName.trim() === '') {
        return res.status(400).json({ message: 'フォルダ名が指定されていません。' });
    }
    
    if (req.files && req.files.length > 0) {
        try {
            // ★DBに「フォルダ名」も一緒に保存する
            const insertPromises = req.files.map(file => {
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`;
                const title = file.key;
                return pool.query(
                    'INSERT INTO images (title, url, folder_name) VALUES ($1, $2, $3)',
                    [title, fileUrl, folderName] // ★$3 に folderName を追加
                );
            });
            
            await Promise.all(insertPromises);
            
            res.json({ 
                message: `「${folderName}」に ${req.files.length} 件の画像をアップロードしました。`,
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

// 3. CSVダウンロード（/download-csv）の処理 (「フォルダ名」も出力するよう改造)
app.get('/download-csv', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT title, url, folder_name FROM images ORDER BY folder_name, created_at DESC');
        
        if (rows.length === 0) {
            res.status(404).send('アップロード履歴がまだありません。');
            return;
        }
        
        // ★ ヘッダーを A列:フォルダ名, B列:題名, C列:URL に変更
        let csvContent = "フォルダ名,題名,URL\n";
        
        rows.forEach(item => {
            const folder = `"${(item.folder_name || 'default').replace(/"/g, '""')}"`;
            const title = `"${item.title.replace(/"/g, '""')}"`;
            const url = `"${item.url.replace(/"/g, '""')}"`;
            csvContent += `${folder},${title},${url}\n`; // ★変更
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

// 4. 【新API】 フォルダリスト取得API (/api/folders)
app.get('/api/folders', async (req, res) => {
    try {
        const queryText = `
            SELECT DISTINCT folder_name 
            FROM images 
            ORDER BY folder_name
        `;
        const { rows } = await pool.query(queryText);
        const folders = rows.map(row => row.folder_name);
        res.json(folders); 
        
    } catch (dbError) {
        console.error('API /api/folders error:', dbError);
        res.status(500).json({ message: 'フォルダの読み込みに失敗しました。' });
    }
});

// 5. 【新API】 特定のフォルダの画像リスト取得API (/api/images/:folderName)
app.get('/api/images/:folderName', async (req, res) => {
    try {
        const { folderName } = req.params; 
        
        const queryText = `
            SELECT title, url 
            FROM images 
            WHERE folder_name = $1 
            ORDER BY created_at DESC
        `;
        const { rows } = await pool.query(queryText, [folderName]); 
        
        res.json(rows); 
        
    } catch (dbError) {
        console.error('API /api/images/:folderName error:', dbError);
        res.status(500).json({ message: '画像の読み込みに失敗しました。' });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    // 起動時にDBテーブルを（必要なら）更新する
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});