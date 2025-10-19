// --- 基本部品の読み込み ---
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const multerS3 = require('multer-s3');
// ▼▼▼ R2から「複数ファイル削除」コマンドを読み込む ▼▼▼
const { S3Client, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
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

// ★ DBテーブル自動改造関数 (変更なし)
const createTable = async () => {
    const createQuery = `
    CREATE TABLE IF NOT EXISTS images (
      id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, url VARCHAR(1024) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      folder_name VARCHAR(100) DEFAULT 'default_folder',
      category_name VARCHAR(100) DEFAULT 'default_category'
    );`;
    const alterFolderQuery = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='images' AND column_name='folder_name') THEN ALTER TABLE images ADD COLUMN folder_name VARCHAR(100) DEFAULT 'default_folder'; END IF; END; $$;`;
    const alterCategoryQuery = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='images' AND column_name='category_name') THEN ALTER TABLE images ADD COLUMN category_name VARCHAR(100) DEFAULT 'default_category'; END IF; END; $$;`;
    try {
        await pool.query(createQuery);
        await pool.query(alterFolderQuery);
        await pool.query(alterCategoryQuery);
        console.log('Database table "images" is ready with "category_name" and "folder_name" columns.');
    } catch (err) {
        console.error('Failed to update database table:', err);
    }
};

// --- 2. ストレージ (Cloudflare R2) 接続 ---
const r2Endpoint = `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const r2PublicUrl = process.env.R2_PUBLIC_URL;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME; // ★ 削除コマンドで使うため、変数に入れておく
const s3Client = new S3Client({
    region: 'auto', endpoint: r2Endpoint,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    },
});

// --- 3. Multer (アップロード処理) 設定 (変更なし) ---
const upload = multer({
    storage: multerS3({
        s3: s3Client, bucket: R2_BUCKET_NAME, acl: 'public-read',
        key: function (req, file, cb) {
            const decodedFilename = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, decodedFilename);
        }
    }),
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) { cb(null, true); } 
        else { cb(new Error('画像ファイルのみアップロード可能です。'), false); }
    }
});

// --- サーバーの処理 ---

// 1. ルート ('/') (変更なし)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. アップロード（/upload） (変更なし)
app.post('/upload', upload.array('imageFiles', 100), async (req, res) => {
    const { categoryName, folderName } = req.body; 
    if (!categoryName || categoryName.trim() === '') { return res.status(400).json({ message: 'カテゴリ名が指定されていません。' }); }
    if (!folderName || folderName.trim() === '') { return res.status(400).json({ message: 'フォルダ名が指定されていません。' }); }
    if (req.files && req.files.length > 0) {
        try {
            const insertPromises = req.files.map(file => {
                const fileUrl = `${r2PublicUrl}/${encodeURIComponent(file.key)}`;
                const title = file.key;
                return pool.query(
                    'INSERT INTO images (title, url, folder_name, category_name) VALUES ($1, $2, $3, $4)',
                    [title, fileUrl, folderName, categoryName]
                );
            });
            await Promise.all(insertPromises);
            res.json({ message: `「${categoryName} / ${folderName}」に ${req.files.length} 件の画像をアップロードしました。` });
        } catch (dbError) {
            console.error('Database insert error:', dbError);
            res.status(500).json({ message: 'データベースへの保存に失敗しました。' });
        }
    } else {
        res.status(400).json({ message: 'アップロードするファイルが選択されていません。' });
    }
});

// 3. フォルダ別CSVダウンロード（/download-csv） (変更なし)
app.get('/download-csv', async (req, res) => {
    try {
        const { folder } = req.query; 
        let queryText; let queryParams;
        if (folder) {
            queryText = 'SELECT title, url, folder_name, category_name FROM images WHERE folder_name = $1 ORDER BY created_at DESC';
            queryParams = [folder];
        } else {
            queryText = 'SELECT title, url, folder_name, category_name FROM images ORDER BY category_name, folder_name, created_at DESC';
            queryParams = [];
        }
        const { rows } = await pool.query(queryText, queryParams);
        if (rows.length === 0) { res.status(404).send('対象の履歴がありません。'); return; }
        let csvContent = "カテゴリ名,フォルダ名,題名,URL\n";
        rows.forEach(item => {
            const category = `"${(item.category_name || 'default').replace(/"/g, '""')}"`;
            const f = `"${(item.folder_name || 'default').replace(/"/g, '""')}"`;
            const title = `"${item.title.replace(/"/g, '""')}"`;
            const url = `"${item.url.replace(/"/g, '""')}"`;
            csvContent += `${category},${f},${title},${url}\n`;
        });
        const fileName = folder ? `upload_list_${folder}.csv` : 'upload_list_all.csv';
        const bom = '\uFEFF';
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.status(200).send(bom + csvContent);
    } catch (dbError) {
        console.error('Database select error:', dbError);
        res.status(500).send('データベースからの読み込みに失敗しました。');
    }
});

// 4. カテゴリリストAPI (/api/categories) (変更なし)
app.get('/api/categories', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT DISTINCT category_name FROM images ORDER BY category_name');
        res.json(rows.map(row => row.category_name)); 
    } catch (dbError) {
        console.error('API /api/categories error:', dbError);
        res.status(500).json({ message: 'カテゴリの読み込みに失敗しました。' });
    }
});

// 5. フォルダリストAPI (/api/folders_by_category/:categoryName) (変更なし)
app.get('/api/folders_by_category/:categoryName', async (req, res) => {
    try {
        const { categoryName } = req.params; 
        const { rows } = await pool.query(
            'SELECT DISTINCT folder_name FROM images WHERE category_name = $1 ORDER BY folder_name', [categoryName]
        );
        res.json(rows.map(row => row.folder_name));
    } catch (dbError) {
        console.error('API /api/folders_by_category error:', dbError);
        res.status(500).json({ message: 'フォルダの読み込みに失敗しました。' });
    }
});

// 6. 画像リストAPI (/api/images_by_folder/:folderName) (変更なし)
app.get('/api/images_by_folder/:folderName', async (req, res) => {
    try {
        const { folderName } = req.params; 
        const { rows } = await pool.query(
            'SELECT title, url FROM images WHERE folder_name = $1 ORDER BY created_at DESC', [folderName]
        ); 
        res.json(rows); 
    } catch (dbError) {
        console.error('API /api/images_by_folder error:', dbError);
        res.status(500).json({ message: '画像の読み込みに失敗しました。' });
    }
});

// ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
// 7. 【新機能】 フォルダ削除API (/api/folder/:folderName)
app.delete('/api/folder/:folderName', async (req, res) => {
    const { folderName } = req.params;
    
    try {
        // --- ステップA: 削除対象のファイル名をDBから取得 ---
        const { rows } = await pool.query(
            'SELECT title FROM images WHERE folder_name = $1', [folderName]
        );

        if (rows.length > 0) {
            // --- ステップB: R2(倉庫)から画像ファイル本体を削除 ---
            
            // R2に送る「削除リスト」を作成 (例: [{ Key: 'image1.jpg' }, { Key: 'image2.png' }])
            const objectsToDelete = rows.map(row => ({ Key: row.title }));

            // R2に「これらを削除しろ」という命令(コマンド)を作成
            const deleteCommand = new DeleteObjectsCommand({
                Bucket: R2_BUCKET_NAME,
                Delete: {
                    Objects: objectsToDelete,
                },
            });

            // R2に命令を送信
            await s3Client.send(deleteCommand);
            console.log(`Successfully deleted ${objectsToDelete.length} objects from R2 for folder: ${folderName}`);
        }

        // --- ステップC: DB(台帳)から履歴を削除 ---
        await pool.query(
            'DELETE FROM images WHERE folder_name = $1', [folderName]
        );
        
        console.log(`Successfully deleted database records for folder: ${folderName}`);
        
        // --- ステップD: 成功をブラウザに返す ---
        res.json({ message: `フォルダ「${folderName}」を完全に削除しました。` });

    } catch (error) {
        console.error(`Failed to delete folder ${folderName}:`, error);
        res.status(500).json({ message: 'フォルダの削除に失敗しました。サーバーエラーが発生しました。' });
    }
});
// ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

// --- サーバーの起動 ---
app.listen(port, async () => {
    await createTable(); 
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});