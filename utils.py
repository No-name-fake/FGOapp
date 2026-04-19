import smtplib
import secrets
import sqlite3
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

# --- SMTP設定 (環境変数から取得) ---
# 実際に使用する際は .env ファイルに設定してください
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")          # 送信元Gmailアドレス
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")  # Googleアプリパスワード(16桁)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")      # お問い合わせの宛先メールアドレス

DB_PATH = os.environ.get("DATABASE_PATH", "fgo_app.db")


def send_email(to_address: str, subject: str, body: str) -> bool:
    """
    Gmailを使ってメールを送信する。

    実際に動作させるには .env ファイルに以下を設定してください:
        SMTP_USER=your_gmail@gmail.com
        SMTP_PASSWORD=your_16_char_app_password

    Args:
        to_address: 送信先メールアドレス
        subject: 件名
        body: 本文 (テキスト形式)

    Returns:
        成功した場合 True、失敗した場合 False
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        # メール設定が未設定の場合はコンソールに出力（開発時）
        print(f"To: {to_address}")
        print(f"{body}")
        return True  # スタブとして成功扱い

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_USER
        msg["To"] = to_address
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_address, msg.as_string())

        return True
    except Exception as e:
        print(f"[MAIL ERROR] メール送信失敗: {e}")
        return False


def generate_reset_token(user_id: int) -> str:
    """
    パスワードリセット用のトークンを生成してDBに保存する。
    有効期限は1時間。

    Args:
        user_id: 対象ユーザーのID

    Returns:
        生成されたトークン文字列 (64桁の16進数)
    """
    token = secrets.token_hex(32)  # 64文字のランダムなトークン
    expires_at = datetime.utcnow() + timedelta(hours=1)

    conn = sqlite3.connect(DB_PATH)
    # 同一ユーザーの古いトークンを削除してから新しいものを挿入
    conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
    conn.execute(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at.strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

    return token


def verify_reset_token(token: str):
    """
    トークンを検証し、有効であればユーザーIDを返す。
    無効または期限切れの場合はNoneを返す。

    Args:
        token: 検証するトークン文字列

    Returns:
        有効な場合はユーザーID(int)、無効な場合はNone
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ?", (token,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    # 有効期限チェック
    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > expires_at:
        return None  # 期限切れ

    return row["user_id"]


def delete_reset_token(token: str):
    """
    使用済みのトークンをDBから削除する（1回限りの有効性を担保）。

    Args:
        token: 削除するトークン文字列
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()
