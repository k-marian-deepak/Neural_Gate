"""
Vulnerable Flask Application for Neural-Gate Testing
Built intentionally with security flaws to demonstrate proxy detection
Database: SQLite (no external deps)
"""

from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_PATH = "test_app.db"

# ============================================================================
# DATABASE SETUP
# ============================================================================

def init_db():
    """Initialize SQLite database with test tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table (vulnerable to SQLi)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    """)
    
    # Posts table (vulnerable to XSS)
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            created_at TEXT
        )
    """)
    
    # Insert sample data
    try:
        c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@test.local')")
        c.execute("INSERT INTO users VALUES (2, 'user1', 'password123', 'user1@test.local')")
        c.execute("INSERT INTO posts VALUES (1, 1, 'Hello', 'This is a test post', '2026-03-07')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Tables already have data
    
    conn.close()

# ============================================================================
# VULNERABLE ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "app": "vulnerable-test-server"}), 200


@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABLE: SQL Injection Vulnerability
    Takes user input and concats it directly into SQL query
    """
    data = request.get_json() or request.form
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # VULNERABLE: Direct string concatenation (SQL Injection!)
    query = f"SELECT id, username, email FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[SQL QUERY] {query}")  # Log for debugging
    
    try:
        c.execute(query)
        user = c.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                "status": "success",
                "user_id": user[0],
                "username": user[1],
                "email": user[2]
            }), 200
        else:
            return jsonify({"status": "failed", "message": "Invalid credentials"}), 401
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/search', methods=['GET'])
def search():
    """
    VULNERABLE: SQL Injection Vulnerability
    Search posts by keyword
    """
    keyword = request.args.get('q', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # VULNERABLE: Direct string concatenation (SQL Injection!)
    query = f"SELECT id, title, content FROM posts WHERE title LIKE '%{keyword}%' OR content LIKE '%{keyword}%'"
    print(f"[SQL QUERY] {query}")
    
    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "results": [{"id": r[0], "title": r[1], "content": r[2]} for r in results]
        }), 200
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/comment', methods=['POST'])
def comment():
    """
    VULNERABLE: Cross-Site Scripting (XSS) Vulnerability
    Takes user comment and stores it without sanitization
    """
    data = request.get_json() or request.form
    post_id = data.get('post_id', 1)
    user_id = data.get('user_id', 1)
    comment_text = data.get('text', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # VULNERABLE: No input sanitization (XSS!)
    c.execute(
        "INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        (user_id, f"Comment on post {post_id}", comment_text, datetime.now().isoformat())
    )
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    
    return jsonify({
        "status": "success",
        "message": "Comment added",
        "id": new_id,
        "comment": comment_text
    }), 201


@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """
    VULNERABLE: Path Traversal / Information Disclosure
    Returns user data based on ID (no access control)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT id, username, email, password FROM users WHERE id={user_id}")
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "password": user[3]  # VULNERABLE: Exposing password!
        }), 200
    return jsonify({"status": "error", "message": "User not found"}), 404


@app.route('/api/export', methods=['GET'])
def export():
    """
    VULNERABLE: Information Disclosure / Exfiltration Risk
    Returns all users (no access control)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, password FROM users")
    users = c.fetchall()
    conn.close()
    
    return jsonify({
        "status": "success",
        "count": len(users),
        "data": [
            {"id": u[0], "username": u[1], "email": u[2], "password": u[3]}
            for u in users
        ]
    }), 200


@app.route('/', methods=['GET'], defaults={'path': ''})
@app.route('/<path:path>', methods=['GET'])
def catch_all(path):
    """Catch-all for any other path"""
    return jsonify({
        "status": "ok",
        "app": "Vulnerable Test Server",
        "path": f"/{path}",
        "endpoints": [
            "GET /health",
            "POST /api/login (username, password)",
            "GET /api/search?q=keyword",
            "POST /api/comment (post_id, user_id, text)",
            "GET /api/user/<id>",
            "GET /api/export"
        ]
    }), 200


if __name__ == '__main__':
    print("[*] Initializing database...")
    init_db()
    
    print("[*] Starting Vulnerable Test Server on http://127.0.0.1:3000")
    print("[!] WARNING: This app has intentional security flaws for testing ONLY")
    print("[!] Do NOT use in production or expose to untrusted networks")
    print()
    
    app.run(host='127.0.0.1', port=3000, debug=False, use_reloader=False)
