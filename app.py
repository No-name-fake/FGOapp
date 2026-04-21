from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import json
import click # CLI用
from dotenv import load_dotenv
from utils import send_email, generate_reset_token, verify_reset_token, delete_reset_token, ADMIN_EMAIL

# .envファイルから環境変数を読み込む
load_dotenv()

app = Flask(__name__)
# 秘密鍵を環境変数から取得（設定されていない場合はデフォルト値を使用）
app.secret_key = os.environ.get("SECRET_KEY", "fgo_secret_key_default")
# データベースのパスを環境変数から取得
DB_PATH = os.environ.get("DATABASE_PATH", "fgo_app.db")

# --- データベース関連 (Database) ---
def get_db_connection():
    """SQLite データベースへの接続を取得し、辞書形式でアクセスできるように設定します"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- 認証用デコレータ (Authentication Decorators) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect(url_for('index'))  # または403エラー
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()

def init_db():
    """データベースの初期化を行います。テーブルが存在しない場合は最新の構造で作成します。"""
    conn = get_db_connection()
    # ユーザーテーブル (emailカラムを含む最新スキーマ)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            email TEXT
        )
    """)
    # --- マイグレーション: 既存DBにemailカラムがなければ追加 ---
    existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "email" not in existing_cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        print("[migration] users テーブルに email カラムを追加しました。")
    # 所持サーヴァントテーブル
    conn.execute("""
        CREATE TABLE IF NOT EXISTS owned_servants (
            user_id INTEGER,
            id INTEGER,
            PRIMARY KEY(user_id, id)
        )
    """)
    # 編成テーブル
    conn.execute("""
        CREATE TABLE IF NOT EXISTS parties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            s1 INTEGER, s2 INTEGER, s3 INTEGER, s4 INTEGER, s5 INTEGER, s6 INTEGER,
            c1 INTEGER, c2 INTEGER, c3 INTEGER, c4 INTEGER, c5 INTEGER, c6 INTEGER,
            s1_sk1 INTEGER DEFAULT 10, s1_sk2 INTEGER DEFAULT 10, s1_sk3 INTEGER DEFAULT 10, s1_np INTEGER DEFAULT 1,
            s2_sk1 INTEGER DEFAULT 10, s2_sk2 INTEGER DEFAULT 10, s2_sk3 INTEGER DEFAULT 10, s2_np INTEGER DEFAULT 1,
            s3_sk1 INTEGER DEFAULT 10, s3_sk2 INTEGER DEFAULT 10, s3_sk3 INTEGER DEFAULT 10, s3_np INTEGER DEFAULT 1,
            s4_sk1 INTEGER DEFAULT 10, s4_sk2 INTEGER DEFAULT 10, s4_sk3 INTEGER DEFAULT 10, s4_np INTEGER DEFAULT 1,
            s5_sk1 INTEGER DEFAULT 10, s5_sk2 INTEGER DEFAULT 10, s5_sk3 INTEGER DEFAULT 10, s5_np INTEGER DEFAULT 1,
            s6_sk1 INTEGER DEFAULT 10, s6_sk2 INTEGER DEFAULT 10, s6_sk3 INTEGER DEFAULT 10, s6_np INTEGER DEFAULT 1,
            mystic_code TEXT DEFAULT 'カルデア',
            mystic_code_id INTEGER DEFAULT 1,
            memo TEXT DEFAULT '',
            turn1 TEXT DEFAULT '',
            turn2 TEXT DEFAULT '',
            turn3 TEXT DEFAULT '',
            category TEXT DEFAULT '',
            location TEXT DEFAULT '',
            location_detail TEXT DEFAULT '',
            difficulty TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # パスワードリセット用トークンテーブル
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# アプリ起動時にDBを初期化
init_db()

# --- ページルーティング (View Routes) ---

@app.route("/")
@login_required
def index():
    """メインページ：サーヴァント一覧とフィルタリング"""
    return render_template("index.html")

@app.route("/registration")
@login_required
def registration():
    """編成登録ページ"""
    return render_template("registration.html")

@app.route("/parties")
@login_required
def parties():
    """投稿済み編成一覧ページ"""
    return render_template("parties.html")

@app.route("/mypage")
@login_required
def mypage():
    """マイページ：自身の統計情報などを表示"""
    conn = get_db_connection()
    party_count = conn.execute("SELECT COUNT(*) FROM parties WHERE user_id = ?", (g.user['id'],)).fetchone()[0]
    owned_count = conn.execute("SELECT COUNT(*) FROM owned_servants WHERE user_id = ?", (g.user['id'],)).fetchone()[0]
    conn.close()
    return render_template("mypage.html", party_count=party_count, owned_count=owned_count)

# --- 認証機能 (Auth: ログイン・会員登録) ---

@app.route("/register", methods=["GET", "POST"])
def register():
    """新規ユーザー登録処理"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email    = request.form.get("email", "").strip() or None
        
        if not username or not password:
            return render_template("register.html", error="ユーザー名とパスワードを入力してください")
            
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user:
            conn.close()
            return render_template("register.html", error="そのユーザー名は既に使われています")
            
        hashed_pw = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, hashed_pw, email)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('login', success="登録が完了しました。ログインしてください。"))
        
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """ログイン処理：セッションにユーザーIDを保持"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('index'))
            
        return render_template("login.html", error="ユーザー名かパスワードが間違っています")
        
    return render_template("login.html")

@app.route("/logout")
def logout():
    """ログアウト処理：セッションを破棄"""
    session.clear()
    return redirect(url_for('login'))


# --- パスワードリセット機能 (Password Reset) ---

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """パスワードリセット申請：登録メールアドレスにリセットリンクを送信"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            return render_template("forgot_password.html", error="メールアドレスを入力してください")

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        # セキュリティのため、メールが存在しない場合も同じメッセージを表示
        if user:
            token = generate_reset_token(user["id"])
            reset_url = url_for("reset_password", token=token, _external=True)
            body = f"""パスワードリセットのご要望を受け付けました。

以下のリンクをクリックしてパスワードを再設定してください。
リンクの有効期限は1時間です。

{reset_url}

このメールに心当たりがない場合は無視してください。"""
            send_email(email, "【Strategy HUB】パスワードリセット", body)

        return render_template("forgot_password.html",
                               success="入力されたメールアドレスに案内を送信しました（登録済みの場合）")

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """トークン検証とパスワード再設定"""
    user_id = verify_reset_token(token)
    if not user_id:
        return render_template("reset_password.html",
                               error="リンクが無効か期限切れです。再度申請してください",
                               token=None)

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(new_password) < 6:
            return render_template("reset_password.html",
                                   error="パスワードは6文字以上で入力してください", token=token)
        if new_password != confirm:
            return render_template("reset_password.html",
                                   error="パスワードが一致しません", token=token)

        hashed = generate_password_hash(new_password)
        conn = get_db_connection()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
        conn.commit()
        conn.close()
        delete_reset_token(token)

        return redirect(url_for("login", success="パスワードを変更しました。新しいパスワードでログインしてください。"))

    return render_template("reset_password.html", token=token)


# --- お問い合わせ機能 (Contact) ---

@app.route("/contact", methods=["GET", "POST"])
def contact():
    """お問い合わせフォーム"""
    if request.method == "POST":
        sender_name  = request.form.get("name", "").strip()
        sender_email = request.form.get("email", "").strip()
        subject      = request.form.get("subject", "").strip()
        message      = request.form.get("message", "").strip()

        if not all([sender_name, sender_email, subject, message]):
            return render_template("contact.html", error="すべての項目を入力してください")

        body = f"""【お問い合わせ】

名前: {sender_name}
メールアドレス: {sender_email}
件名: {subject}

内容:
{message}
"""
        send_email(ADMIN_EMAIL or sender_email, f"[お問い合わせ] {subject}", body)
        return render_template("contact.html",
                               success="お問い合わせを受け付けました。ありがとうございました。")

    return render_template("contact.html")

# --- 所持状況 API (Owned Servants API) ---

@app.route("/api/owned", methods=["GET"])
@login_required
def get_owned():
    """ログインユーザーの所持サーヴァントID一覧を取得"""
    conn = get_db_connection()
    rows = conn.execute("SELECT id FROM owned_servants WHERE user_id = ?", (g.user['id'],)).fetchall()
    conn.close()
    return jsonify([row["id"] for row in rows])

@app.route("/api/owned", methods=["POST"])
@login_required
def update_owned():
    """所持サーヴァントの状態（持っているかいないか）を更新"""
    data = request.json
    servant_id = data.get("id")
    owned = data.get("owned") # True or False
    
    conn = get_db_connection()
    if owned:
        conn.execute("INSERT OR IGNORE INTO owned_servants (user_id, id) VALUES (?, ?)", (g.user['id'], servant_id))
    else:
        conn.execute("DELETE FROM owned_servants WHERE user_id = ? AND id = ?", (g.user['id'], servant_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# --- 編成 API (Parties API) ---

@app.route("/api/parties", methods=["GET"])
@login_required
def get_parties():
    """ログインユーザー自身のパーティ編成一覧を取得"""
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM parties WHERE user_id = ? ORDER BY created_at DESC", (g.user['id'],)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/parties", methods=["POST"])
@login_required
def save_party():
    """新しいパーティ編成をデータベースに保存"""
    data = request.json
    user_id   = g.user['id']
    name      = data.get("name", "新しい編成")
    servants  = data.get("servants", [])
    ces       = data.get("ces", [])
    skills    = data.get("skills", [])
    nps       = data.get("nps", [])
    mystic_code     = data.get("mystic_code", "カルデア")
    mystic_code_id  = data.get("mystic_code_id", 1)
    memo            = data.get("memo", "")[:1000]
    category        = data.get("category", "")[:20]
    location        = data.get("location", "")[:20]
    location_detail = data.get("location_detail", "")[:30]
    difficulty      = data.get("difficulty", "")[:20]
    
    # 6体分になるようにパディング
    while len(servants) < 6: servants.append(None)
    while len(ces) < 6: ces.append(None)
    while len(skills) < 6: skills.append([10, 10, 10])
    while len(nps) < 6: nps.append(1)
    
    # クエリ用引数リスト作成
    args = [user_id, name]
    args.extend(servants[:6])
    args.extend(ces[:6])
    for i in range(6):
        args.extend(skills[i][:3])
        args.append(nps[i])
    args.extend([mystic_code, mystic_code_id, memo, category, location, location_detail, difficulty])
    
    placeholders = ",".join(["?"] * len(args))
    
    # カラム名の構築
    cols = "user_id, name, "
    cols += "s1, s2, s3, s4, s5, s6, "
    cols += "c1, c2, c3, c4, c5, c6, "
    for i in range(1, 7):
        cols += f"s{i}_sk1, s{i}_sk2, s{i}_sk3, s{i}_np, "
    cols += "mystic_code, mystic_code_id, memo, category, location, location_detail, difficulty"
    
    conn = get_db_connection()
    conn.execute(f"INSERT INTO parties ({cols}) VALUES ({placeholders})", args)
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/parties/<int:party_id>", methods=["DELETE"])
@login_required
def delete_party(party_id):
    """特定のパーティ編成を削除（自身のものに限る）"""
    conn = get_db_connection()
    conn.execute("DELETE FROM parties WHERE id = ? AND user_id = ?", (party_id, g.user['id']))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# --- 管理画面 (Admin Dashboard) ---

@app.route("/admin")
@admin_required
def admin():
    """管理画面のメインページ"""
    return render_template("admin.html")

@app.route("/api/admin/stats")
@admin_required
def get_stats():
    """システム全体の統計情報を取得"""
    conn = get_db_connection()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    owned_count = conn.execute("SELECT COUNT(*) FROM owned_servants").fetchone()[0]
    party_count = conn.execute("SELECT COUNT(*) FROM parties").fetchone()[0]
    conn.close()
    return jsonify({
        "user_count": user_count,
        "owned_count": owned_count,
        "party_count": party_count
    })

@app.route("/api/admin/reset_owned", methods=["POST"])
@admin_required
def reset_owned():
    """【危険】全ユーザーの所持情報をリセット"""
    conn = get_db_connection()
    conn.execute("DELETE FROM owned_servants")
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/admin/parties", methods=["GET"])
@admin_required
def admin_get_parties():
    """全ユーザーのパーティ編成一覧をユーザー名付きで取得"""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT p.*, u.username 
        FROM parties p 
        LEFT JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/admin/parties/<int:party_id>", methods=["DELETE"])
@admin_required
def admin_delete_party(party_id):
    """管理権限で特定のパーティを削除"""
    conn = get_db_connection()
    conn.execute("DELETE FROM parties WHERE id = ?", (party_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# --- ユーザー管理 API ---
@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_get_users():
    conn = get_db_connection()
    rows = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({"status": "error", "message": "自分自身を削除することはできません"}), 400
    
    conn = get_db_connection()
    # ユーザーに関連するデータも削除
    conn.execute("DELETE FROM parties WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM owned_servants WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/admin/users/<int:user_id>/toggle_admin", methods=["POST"])
@admin_required
def admin_toggle_user_admin(user_id):
    if user_id == session.get('user_id'):
        return jsonify({"status": "error", "message": "自分自身の権限は変更できません"}), 400
        
    conn = get_db_connection()
    user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_status = 1 if not user['is_admin'] else 0
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# --- 全所持状況管理 API ---
@app.route("/api/admin/owned", methods=["GET"])
@admin_required
def admin_get_owned():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT o.*, u.username 
        FROM owned_servants o 
        LEFT JOIN users u ON o.user_id = u.id
    """).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/admin/owned/<int:user_id>/<int:servant_id>", methods=["DELETE"])
@admin_required
def admin_delete_owned_record(user_id, servant_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM owned_servants WHERE user_id = ? AND id = ?", (user_id, servant_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# --- エラーハンドリング (Error Handling) ---

@app.errorhandler(500)
def internal_error(e):
    """500エラー時のログ出力とレスポンス"""
    import traceback
    print("500 Internal Server Error:")
    traceback.print_exc()
    return "Internal Server Error", 500

# --- カスタム CLI コマンド (Custom Flask CLI Commands) ---
# これにより `flask admin create <user> <pass>` のようにコマンドラインから管理操作が可能になります

@app.cli.group()
def admin():
    """管理者ユーザーの管理用コマンドグループ"""
    pass

@admin.command("create")
@click.argument("username")
@click.argument("password")
def create_admin_user(username, password):
    """管理者ユーザーを新規作成または既存ユーザーをアップグレードします"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    existing = cursor.execute("SELECT id, is_admin FROM users WHERE username = ?", (username,)).fetchone()
    
    if existing:
        if existing['is_admin']:
            click.echo(f"エラー: ユーザー '{username}' は既に管理者です。")
        else:
            cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
            click.echo(f"完了: 既存ユーザー '{username}' を管理者にアップグレードしました。")
    else:
        hashed_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", (username, hashed_pw))
        click.echo(f"完了: 管理者ユーザー '{username}' を新規作成しました。")
    
    conn.commit()
    conn.close()

@admin.command("list")
def list_admins():
    """管理者ユーザーの一覧を表示します"""
    conn = get_db_connection()
    users = conn.execute("SELECT id, username FROM users WHERE is_admin = 1").fetchall()
    conn.close()
    
    if not users:
        click.echo("管理者は登録されていません。")
        return
        
    click.echo("--- 管理者一覧 ---")
    for u in users:
        click.echo(f"ID: {u['id']} | Username: {u['username']}")

@admin.command("delete")
@click.argument("username")
def delete_admin_flag(username):
    """ユーザーの管理者権限を剥奪します（ユーザー自体は削除されません）"""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    
    if not user:
        click.echo(f"エラー: ユーザー '{username}' が見つかりません。")
        conn.close()
        return
        
    conn.execute("UPDATE users SET is_admin = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    click.echo(f"完了: ユーザー '{username}' の管理者権限を剥奪しました。")

if __name__ == "__main__":
    # デバッグモードでアプリを起動 (port: 5000)
    app.run(debug=True, port=5000)
