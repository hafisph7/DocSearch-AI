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
from dotenv import load_dotenv

# ================= LOAD ENV =================
load_dotenv()

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
    user_folder = os.path.join("uploads", user_email)

    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No file selected"}), 400

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    filepath = os.path.join(user_folder, file.filename)
    file.save(filepath)

    # Extract text and save it to a companion file for privacy and performance
    extracted_text = ""
    try:
        if file.filename.lower().endswith(".pdf"):
            with pdfplumber.open(filepath) as pdf:
                for page in pdf.pages:
                    extracted_text += page.extract_text() or ""
        
        # Save extracted text to a hidden file for this user
        text_filepath = filepath + ".txt"
        with open(text_filepath, "w", encoding="utf-8") as f:
            f.write(extracted_text)
            
        return jsonify({"message": "File uploaded successfully"})
    except Exception as e:
        return jsonify({"message": f"Error processing file: {str(e)}"}), 500

# ================= LIST FILES =================
@app.route("/files", methods=["GET"])
def list_files():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    user_folder = os.path.join("uploads", user_email)

    if not os.path.exists(user_folder):
        return jsonify([])
        
    files = []
    for filename in os.listdir(user_folder):
        filepath = os.path.join(user_folder, filename)
        # Only show the original files, not the extracted text files
        if os.path.isfile(filepath) and not filename.endswith(".txt"):
            stats = os.stat(filepath)
            files.append({
                "name": filename,
                "size": f"{stats.st_size / (1024 * 1024):.2f} MB",
                "date": os.path.getmtime(filepath)
            })
    return jsonify(files)

# ================= DELETE FILE =================
@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    user_email = session["user"]
    filepath = os.path.join("uploads", user_email, filename)
    text_filepath = filepath + ".txt"

    if os.path.exists(filepath):
        os.remove(filepath)
        if os.path.exists(text_filepath):
            os.remove(text_filepath)
        return jsonify({"message": "File deleted successfully"})
    else:
        return jsonify({"message": "File not found"}), 404

# ================= ASK QUESTION =================
@app.route("/ask", methods=["POST"])
def ask_question():
    if "user" not in session:
        return jsonify({"answer": "Unauthorized"}), 403

    user_email = session["user"]
    user_folder = os.path.join("uploads", user_email)

    if not os.path.exists(user_folder):
        return jsonify({"answer": "Please upload a document first."})

    # Find all extracted text files for this user
    text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
    if not text_files:
        return jsonify({"answer": "No extracted text found. Please upload your documents again."})
    
    # Combine text from all documents (with a limit to prevent prompt overflow)
    all_text = []
    for f in text_files:
        with open(os.path.join(user_folder, f), "r", encoding="utf-8") as file:
            all_text.append(file.read())
    
    document_text = "\n\n".join(all_text)

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
            return jsonify(data)
        except Exception:
            # Fallback if AI didn't return valid JSON
            return jsonify({"answer": ai_text, "resources": {"practice": [], "videos": []}})

    except Exception as e:
        print(f"DEBUG: AI Error: {str(e)}")
        return jsonify({"answer": f"AI Error occurred: {str(e)}", "resources": {"practice": [], "videos": []}})

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
    print("🌍 PLEASE OPEN THIS LINK IN YOUR BROWSER:")
    print("👉 http://localhost:5000")
    print("****************************************************************\n")
    
    # Use localhost specifically to match OAuth Redirect URIs
    app.run(debug=True, host='127.0.0.1', port=5000)
