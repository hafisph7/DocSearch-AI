import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.linkedin import make_linkedin_blueprint, linkedin
from flask_mail import Mail, Message
import sqlite3
import psycopg2
import psycopg2.extras
import bcrypt
import pdfplumber
import google.generativeai as genai
from supabase import create_client, Client
from dotenv import load_dotenv

# ================= LOAD ENV =================
load_dotenv()

# ================= SUPABASE SETUP =================
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ckcrqhunkdeuotcjhiqn.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNrY3JxaHVua2RldW90Y2poaXFuIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODgyNTgzMSwiZXhwIjoyMDk0NDAxODMxfQ.mXVlhTWlF9wij5dQkARv53_MSHOmV01MHsac5LmbaIg")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Use /tmp for uploads on Vercel as the normal filesystem is read-only
UPLOAD_FOLDER = '/tmp' if os.getenv("DATABASE_URL") else 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ================= FLASK APP =================
app = Flask(__name__)
app.secret_key = "super_secret_key_hafis"
app.config.update(
    SESSION_COOKIE_NAME="docsearch_session",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=2592000  # 30 days to "remember me"
)
CORS(app, supports_credentials=True)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ================= MAIL SETUP =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)

# ================= GEMINI SETUP =================
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("models/gemini-flash-latest")

# ================= OAUTH BLUEPRINTS =================
from flask_dance.consumer import oauth_authorized

# ---------- helper: DB connection ----------
def get_db_connection():
    """Returns a connection to either PostgreSQL (prod) or SQLite (local)."""
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        # Connect to PostgreSQL (Supabase/Render)
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        return conn
    else:
        # Fallback to local SQLite
        conn = sqlite3.connect("users.db", timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

def _save_social_user(email, name, provider):
    """Upsert the social user into the DB and populate the Flask session."""
    if not email:
        email = f"{provider}_{name.replace(' ','_').lower()}@oauth.local"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("SELECT name FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT name FROM users WHERE email = ?", (email,))
        
        user = cursor.fetchone()
        if not user:
            if os.getenv("DATABASE_URL"):
                cursor.execute(
                    "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                    (name, email, psycopg2.Binary(f"{provider}_oauth".encode("utf-8")))
                )
            else:
                cursor.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, f"{provider}_oauth".encode("utf-8"))
                )
            session["user_name"] = name
        else:
            session["user_name"] = user[0]

        session["user"] = email
        session.permanent = True
        session.modified = True
        print(f"DEBUG: {provider} login OK — session user set to {email}")
    finally:
        conn.close()

# Google blueprint  (redirect_url sends browser to /dashboard after authorized)
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["openid", "email", "profile"],
    redirect_url="/dashboard?social=google"
)
app.register_blueprint(google_bp, url_prefix="/login")

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    """Runs inside Flask-Dance's /login/google/authorized handler.
    We set the session here and return False so the token is never
    written to the session cookie (prevents 4 KB overflow)."""
    if not token:
        print("DEBUG: Google — no token received")
        return False
    try:
        resp = blueprint.session.get("/oauth2/v2/userinfo")
        if resp.ok:
            info = resp.json()
            _save_social_user(info.get("email", ""), info.get("name", "Google User"), "google")
        else:
            print(f"DEBUG: Google userinfo fetch failed: {resp.status_code}")
    except Exception as exc:
        print(f"DEBUG: Google signal error: {exc}")
    return False  # <-- Do NOT store token in session

# Facebook blueprint
facebook_bp = make_facebook_blueprint(
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    scope=["email"],
    redirect_url="/dashboard?social=facebook"
)
app.register_blueprint(facebook_bp, url_prefix="/login")

@oauth_authorized.connect_via(facebook_bp)
def facebook_logged_in(blueprint, token):
    if not token:
        return False
    try:
        resp = blueprint.session.get("/me?fields=id,name,email")
        if resp.ok:
            info = resp.json()
            _save_social_user(info.get("email", ""), info.get("name", "Facebook User"), "facebook")
        else:
            print(f"DEBUG: Facebook userinfo fetch failed: {resp.status_code}")
    except Exception as exc:
        print(f"DEBUG: Facebook signal error: {exc}")
    return False

# LinkedIn blueprint
linkedin_bp = make_linkedin_blueprint(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    scope=["openid", "profile", "email"],
    redirect_url="/dashboard?social=linkedin"
)
app.register_blueprint(linkedin_bp, url_prefix="/login")

@oauth_authorized.connect_via(linkedin_bp)
def linkedin_logged_in(blueprint, token):
    if not token:
        return False
    try:
        resp = blueprint.session.get("userinfo")
        if resp.ok:
            info = resp.json()
            _save_social_user(info.get("email", ""), info.get("name", "LinkedIn User"), "linkedin")
        else:
            print(f"DEBUG: LinkedIn userinfo fetch failed: {resp.status_code}")
    except Exception as exc:
        print(f"DEBUG: LinkedIn signal error: {exc}")
    return False

# ================= DATABASE INIT =================
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if os.getenv("DATABASE_URL"):
        # PostgreSQL schema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT,
                email TEXT UNIQUE,
                password BYTEA
            )
        """)
    else:
        # SQLite schema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                password BLOB
            )
        """)
    
    # Create documents table
    if os.getenv("DATABASE_URL"):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                user_email TEXT NOT NULL,
                filename TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                filename TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # Create query_history table
    if os.getenv("DATABASE_URL"):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                id SERIAL PRIMARY KEY,
                user_email TEXT NOT NULL,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                resources TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                filename_context TEXT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                resources TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Wait, filename_context is not strictly needed, but let's keep it simple and consistent:
        # We will use the same schema for SQLite:
        # id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, resources TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        # Let's adjust SQLite schema to match PostgreSQL:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                resources TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    if not os.getenv("DATABASE_URL"):
        conn.commit()
    conn.close()

try:
    init_db()
except Exception as e:
    print(f"CRITICAL: Database initialization failed: {str(e)}")

# ================= GLOBAL STORAGE =================
# We avoid global variables for user-specific data to prevent privacy leaks.
# Each user will have their own folder in 'uploads/'.

@app.before_request
def enforce_localhost():
    """
    Force all traffic to exactly 'localhost:5000' instead of '127.0.0.1:5000'.
    Cookie domains are STRICT. If a user starts login on 127.0.0.1, the state cookie
    is saved there. When Google redirects back to localhost:5000, the browser finds 
    NO cookie, failing state validation and aborting the login silently.
    """
    if request.host.startswith("127.0.0.1"):
        return redirect(request.url.replace("127.0.0.1", "localhost", 1))

# ================= ROUTES =================
@app.route("/")
def index():
    user = session.get("user")
    print(f"DEBUG: Index access. Session user: {user}")
    
    if user:
        return redirect(url_for("dashboard"))
        
    return render_template("index.html")

# ================= SIGN UP =================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                (name, email, psycopg2.Binary(hashed_password))
            )
        else:
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, hashed_password)
            )
        
        if not os.getenv("DATABASE_URL"):
            conn.commit()
        return jsonify({"message": "User Registered Successfully"})
    except (sqlite3.IntegrityError, psycopg2.errors.UniqueViolation):
        return jsonify({"message": "Email already exists"}), 400
    except Exception as e:
        print(f"ERROR DETECTED in /signup: {str(e)}")
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# ================= SIGN IN =================
@app.route("/signin", methods=["POST"])
def signin():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("SELECT name, password FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT name, password FROM users WHERE email = ?", (email,))
        
        user = cursor.fetchone()
        
        if user:
            db_password = bytes(user[1])
            if bcrypt.checkpw(password.encode("utf-8"), db_password):
                session["user_name"] = user[0]
                session["user"] = email
                session.permanent = True
                session.modified = True
                return jsonify({"message": "Login Successful"})
        
        return jsonify({"message": "Invalid Credentials"}), 400
    except Exception as e:
        print(f"ERROR DETECTED in /signin: {str(e)}")
        return jsonify({"message": "Login Error"}), 500
    finally:
        conn.close()

# ================= FORGOT PASSWORD =================
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        
        user = cursor.fetchone()

        if user:
            # Send a real email
            try:
                msg = Message(
                    "Password Reset - DocSearch AI",
                    recipients=[email]
                )
                msg.body = f"""Hello,

You requested a password reset for your DocSearch AI account.
To reset your password, please click the link below:

{request.host_url}?mode=reset&email={email}

If you did not request this, please ignore this email.
"""
                mail.send(msg)
                print(f"DEBUG: Password reset email sent to {email}")
                return jsonify({"message": "Password reset link sent to your email."})
            except Exception as e:
                print(f"DEBUG: Error sending email: {str(e)}")
                return jsonify({"message": "Error sending email. Please check your configuration."}), 500
        else:
            return jsonify({"message": "Email not found"}), 404
    finally:
        conn.close()

# ================= UPDATE PASSWORD =================
@app.route("/update-password", methods=["POST"])
def update_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("new_password")

    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (psycopg2.Binary(hashed_password), email))
        else:
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        
        if not os.getenv("DATABASE_URL"):
            conn.commit()
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# ================= SOCIAL LOGIN TRIGGER ROUTES =================
# These just kick off the OAuth flow. All user-saving logic is in the
# oauth_authorized signals above.

@app.route("/google_login")
def google_login():
    print(f"DEBUG: Starting Google Login")
    try: del google_bp.token
    except Exception: pass
    return redirect(url_for("google.login"))

@app.route("/facebook_login")
def facebook_login():
    print(f"DEBUG: Starting Facebook Login")
    try: del facebook_bp.token
    except Exception: pass
    return redirect(url_for("facebook.login"))

@app.route("/linkedin_login")
def linkedin_login():
    print(f"DEBUG: Starting LinkedIn Login")
    try: del linkedin_bp.token
    except Exception: pass
    return redirect(url_for("linkedin.login"))

# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():
    print(f"DEBUG: Accessing dashboard. Session user: {session.get('user')}")
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")


# ================= FILE UPLOAD =================
@app.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    user_email = session["user"]

    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No file selected"}), 400

    try:
        filename = file.filename
        # Save to /tmp for processing
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Upload to Supabase Storage (Private folder per user)
        supabase_path = f"{user_email}/{filename}"
        with open(filepath, "rb") as f:
            supabase.storage.from_("pdfs").upload(supabase_path, f, {"upsert": "true"})

        # Extract text for AI
        extracted_text = ""
        if filename.lower().endswith(".pdf"):
            with pdfplumber.open(filepath) as pdf:
                for page in pdf.pages:
                    extracted_text += page.extract_text() or ""
        
        # Save metadata to DB
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            if os.getenv("DATABASE_URL"):
                cursor.execute(
                    "INSERT INTO documents (user_email, filename, text) VALUES (%s, %s, %s)",
                    (user_email, filename, extracted_text)
                )
            else:
                cursor.execute(
                    "INSERT INTO documents (user_email, filename, text) VALUES (?, ?, ?)",
                    (user_email, filename, extracted_text)
                )
            if not os.getenv("DATABASE_URL"):
                conn.commit()
            
            # Clean up /tmp
            if os.path.exists(filepath):
                os.remove(filepath)

            return jsonify({"message": "File uploaded successfully"})
        finally:
            conn.close()
    except Exception as e:
        print(f"UPLOAD ERROR: {str(e)}")
        return jsonify({"message": f"Error processing file: {str(e)}"}), 500

# ================= LIST FILES =================
@app.route("/files", methods=["GET"])
def list_files():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    try:
        # List files from Supabase Storage
        res = supabase.storage.from_("pdfs").list(user_email)
        
        files = []
        for item in res:
            files.append({
                "name": item["name"],
                "size": f"{item['metadata']['size'] / (1024 * 1024):.2f} MB",
                "date": item["created_at"]
            })
        return jsonify(files)
    except Exception as e:
        print(f"LIST ERROR: {str(e)}")
        return jsonify([])

# ================= DELETE FILE =================
@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    try:
        # Delete from Supabase Storage
        supabase.storage.from_("pdfs").remove([f"{user_email}/{filename}"])
        
        # Delete from Database
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            if os.getenv("DATABASE_URL"):
                cursor.execute("DELETE FROM documents WHERE user_email = %s AND filename = %s", (user_email, filename))
            else:
                cursor.execute("DELETE FROM documents WHERE user_email = ? AND filename = ?", (user_email, filename))
            if not os.getenv("DATABASE_URL"):
                conn.commit()
            return jsonify({"message": "File deleted successfully"})
        finally:
            conn.close()
    except Exception as e:
        print(f"DELETE ERROR: {str(e)}")
        return jsonify({"message": f"Delete failed: {str(e)}"}), 500

# ================= ASK QUESTION =================
# ================= SAVE QUERY HISTORY =================
def save_query_history(user_email, question, answer, resources_dict):
    import json
    resources_json = json.dumps(resources_dict)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute(
                "INSERT INTO query_history (user_email, question, answer, resources) VALUES (%s, %s, %s, %s)",
                (user_email, question, answer, resources_json)
            )
        else:
            cursor.execute(
                "INSERT INTO query_history (user_email, question, answer, resources) VALUES (?, ?, ?, ?)",
                (user_email, question, answer, resources_json)
            )
        if not os.getenv("DATABASE_URL"):
            conn.commit()
    except Exception as e:
        print(f"DEBUG: Error saving query history: {e}")
    finally:
        conn.close()

# ================= ASK QUESTION =================
@app.route("/ask", methods=["POST"])
def ask_question():
    if "user" not in session:
        return jsonify({"answer": "Unauthorized"}), 403

    user_email = session["user"]
    
    # Get combined text from ALL documents for this user from the Database
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("SELECT text FROM documents WHERE user_email = %s", (user_email,))
        else:
            cursor.execute("SELECT text FROM documents WHERE user_email = ?", (user_email,))
        
        rows = cursor.fetchall()
        if not rows:
            return jsonify({"answer": "Please upload a document first."})
        
        all_text = [row[0] for row in rows]
        document_text = "\n\n".join(all_text)
    finally:
        conn.close()

    data = request.json
    question = data.get("question")

    prompt = f"""
    You are an expert technical AI assistant. Use the provided document as context, but prioritize answering the user's question accurately.

    Document Content:
    {document_text[:8000]}

    User's Question:
    {question}

    Your Task:
    1. Direct Answer: Answer the question based on the document. If the document doesn't contain the answer, answer based on your general knowledge but mention it's not in the document.
    2. Practice Resources: Suggest 3 HIGHLY RELEVANT links (Official docs, GitHub, or specialized sites) that directly help the user with their SPECIFIC QUESTION ({question}).
    3. Video Tutorials: Suggest 3 YouTube search-based URLs that are precisely targeted to the user's question.

    LINK RULES:
    - For practice resources, use direct URLs to official documentation or relevant GitHub search results.
    - For videos, use URLs like: https://www.youtube.com/results?search_query=...

    Return ONLY a JSON object:
    {{
        "answer": "your detailed response here",
        "resources": {{
            "practice": [
                {{ "title": "Specific Title", "desc": "How this relates to '{question}'", "link": "https://..." }}
            ],
            "videos": [
                {{ "title": "Video Topic", "desc": "Why this is useful for '{question}'", "link": "https://www.youtube.com/results?search_query=..." }}
            ]
        }}
    }}
    """

    try:
        response = model.generate_content(prompt)
        ai_text = response.text
        # Try to parse JSON from the response
        text = ai_text.replace("```json", "").replace("```", "").strip()
        
        try:
            import json
            data = json.loads(text)
            # Ensure the structure matches what the frontend expects
            if "answer" not in data:
                data = {"answer": text, "resources": {"practice": [], "videos": []}}
            
            save_query_history(user_email, question, data["answer"], data.get("resources", {"practice": [], "videos": []}))
            return jsonify(data)
        except Exception:
            # Fallback if AI didn't return valid JSON
            fallback_data = {"answer": ai_text, "resources": {"practice": [], "videos": []}}
            save_query_history(user_email, question, fallback_data["answer"], fallback_data["resources"])
            return jsonify(fallback_data)

    except Exception as e:
        print(f"DEBUG: AI Error: {str(e)}")
        return jsonify({"answer": f"AI Error occurred: {str(e)}", "resources": {"practice": [], "videos": []}})

# ================= QUERY HISTORY API =================
@app.route("/history", methods=["GET"])
def get_history():
    if "user" not in session:
        return jsonify([]), 403
    
    user_email = session["user"]
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute(
                "SELECT id, question, answer, resources, created_at FROM query_history WHERE user_email = %s ORDER BY created_at DESC",
                (user_email,)
            )
        else:
            cursor.execute(
                "SELECT id, question, answer, resources, created_at FROM query_history WHERE user_email = ? ORDER BY created_at DESC",
                (user_email,)
            )
        
        rows = cursor.fetchall()
        history = []
        import json
        for row in rows:
            try:
                res_dict = json.loads(row[3])
            except Exception:
                res_dict = {"practice": [], "videos": []}
                
            history.append({
                "id": row[0],
                "question": row[1],
                "answer": row[2],
                "resources": res_dict,
                "created_at": str(row[4])
            })
        return jsonify(history)
    except Exception as e:
        print(f"DEBUG: Error retrieving history: {e}")
        return jsonify([])
    finally:
        conn.close()

@app.route("/history/<int:history_id>", methods=["DELETE"])
def delete_history_item(history_id):
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("DELETE FROM query_history WHERE id = %s AND user_email = %s", (history_id, user_email))
        else:
            cursor.execute("DELETE FROM query_history WHERE id = ? AND user_email = ?", (history_id, user_email))
        
        if not os.getenv("DATABASE_URL"):
            conn.commit()
        return jsonify({"message": "History item deleted successfully"})
    except Exception as e:
        print(f"DEBUG: Error deleting history item: {e}")
        return jsonify({"message": "Failed to delete history item"}), 500
    finally:
        conn.close()

@app.route("/history/clear", methods=["DELETE"])
def clear_history():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if os.getenv("DATABASE_URL"):
            cursor.execute("DELETE FROM query_history WHERE user_email = %s", (user_email,))
        else:
            cursor.execute("DELETE FROM query_history WHERE user_email = ?", (user_email,))
        
        if not os.getenv("DATABASE_URL"):
            conn.commit()
        return jsonify({"message": "History cleared successfully"})
    except Exception as e:
        print(f"DEBUG: Error clearing history: {e}")
        return jsonify({"message": "Failed to clear history"}), 500
    finally:
        conn.close()

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    # Clear OAuth tokens
    for bp in ['google', 'facebook', 'linkedin']:
        if bp in app.blueprints:
            try:
                del app.blueprints[bp].token
            except:
                pass
    session.clear()
    return redirect(url_for("index"))


# ================= RUN =================
if __name__ == "__main__":
    # Print the exact redirect URIs for the user to copy-paste
    print("\n--- OAUTH REDIRECT URIS (Copy these exactly to your portals) ---")
    print("Google:   http://localhost:5000/login/google/authorized")
    print("Facebook: http://localhost:5000/login/facebook/authorized")
    print("LinkedIn: http://localhost:5000/login/linkedin/authorized")
    print("****************************************************************")
    print("PLEASE OPEN THIS LINK IN YOUR BROWSER:")
    print("http://localhost:5000")
    print("****************************************************************\n")
    
    # Use localhost specifically to match OAuth Redirect URIs
    app.run(debug=True, host='127.0.0.1', port=5000)
