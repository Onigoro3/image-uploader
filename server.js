const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();
const port = 3000;

// アップロード履歴をサーバーのメモリ上に保存する配列
// (注：サーバーを再起動すると履歴は消えます)
let uploadHistory = [];

// --- Multer（ファイル保存）の設定 ---

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    
    filename: (req, file, cb) => {
        // 元のファイル名をそのまま使う
        // 日本語ファイル名が文字化けするのを防ぐためのデコード処理
        const decodedFilename = Buffer.from(file.originalname, 'latin1').toString('utf8');
        
        // ★注意: この方法では、同じファイル名の画像がアップロードされると
        // 古いファイルが上書きされます。
        cb(null, decodedFilename);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('画像ファイルのみアップロード可能です。'), false);
        }
    }
});

// --- サーバーのルーティング（URLごとの処理）設定 ---

// 1. ルートURL ('/') にアクセスしたら index.html を表示
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. '/uploads' ディレクトリを静的ファイルとして公開
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 3. '/upload' へのPOSTリクエスト（ファイルアップロード）の処理
// (★「一括アップロード」に対応したバージョンです)
app.post('/upload', upload.array('imageFiles', 100), (req, res) => {
    // 'upload.single' から 'upload.array' に変更
    // 'imageFiles' はHTML側と合わせる名前。100は一度にアップロードできる最大ファイル数

    // ファイルが正常にアップロードされた場合
    if (req.files && req.files.length > 0) {
        
        const baseUrl = req.protocol + '://' + req.get('host');
        
        // ★受け取ったファイルの配列(req.files)をループ処理
        req.files.forEach(file => {
            // ★注意: ファイル名に日本語や空白が含まれる場合、URLエンコードが必要です
            const encodedFilename = encodeURIComponent(file.filename);
            const fileUrl = `${baseUrl}/uploads/${encodedFilename}`;
            
            // 履歴配列に「題名（ファイル名）」と「URL」を一件ずつ追加
            uploadHistory.push({
                title: file.filename, // 元のファイル名
                url: fileUrl              // 生成されたURL
            });
        });

        // JSON形式で「成功メッセージ」と「処理件数」を返す
        res.json({ 
            message: `${req.files.length} 件の画像をアップロードしました。`,
            count: req.files.length
        });

    } else {
        // ファイルが1件もなかった場合
        res.status(400).json({ message: 'アップロードするファイルが選択されていません。' });
    }
}, (error, req, res, next) => {
    // Multerのエラーハンドリング
    res.status(400).json({ message: error.message });
});

// 4. CSVダウンロード処理 (変更なし)
app.get('/download-csv', (req, res) => {
    
    if (uploadHistory.length === 0) {
        res.status(404).send('アップロード履歴がまだありません。');
        return;
    }

    // CSVのヘッダー行を作成（A列は空欄, B列:題名, C列:URL）
    let csvContent = ",題名,URL\n";

    // CSVのデータ行を作成
    uploadHistory.forEach(item => {
        // CSV内で値がカンマや改行を含んでも崩れないよう、" "で囲む（簡易エスケープ）
        const title = `"${item.title.replace(/"/g, '""')}"`;
        const url = `"${item.url.replace(/"/g, '""')}"`;
        
        // A列を空欄にするため、先頭にカンマを追加
        csvContent += `,${title},${url}\n`;
    });

    // Excelなどで日本語CSVを開いた際の文字化けを防ぐため、BOM (Byte Order Mark) を先頭に追加
    const bom = '\uFEFF';

    // HTTPヘッダーを設定
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    // 'attachment' はブラウザにダウンロードを促す設定
    res.setHeader('Content-Disposition', 'attachment; filename="upload_list.csv"');
    
    // BOMとCSVデータを送信
    res.status(200).send(bom + csvContent);
});

// --- サーバーの起動 ---
app.listen(port, () => {
    console.log(`サーバーが http://localhost:${port} で起動しました`);
});