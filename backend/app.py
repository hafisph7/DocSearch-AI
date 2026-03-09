import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_cors import CORS
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.linkedin import make_linkedin_blueprint, linkedin
from flask_mail import Mail, Message
import sqlite3
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
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_DOMAIN=None,
    PERMANENT_SESSION_LIFETIME=3600
)
CORS(app, supports_credentials=True)

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
# Google
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["openid", "email", "profile"],
)
app.register_blueprint(google_bp, url_prefix="/login")

# Facebook
facebook_bp = make_facebook_blueprint(
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    scope=["email"],
)
app.register_blueprint(facebook_bp, url_prefix="/login")

# LinkedIn
linkedin_bp = make_linkedin_blueprint(
    client_id=os.getenv("LINKEDIN_CLIENT_ID"),
    client_secret=os.getenv("LINKEDIN_CLIENT_SECRET"),
    scope=["openid", "profile", "email"],
)
app.register_blueprint(linkedin_bp, url_prefix="/login")

# ================= DATABASE INIT =================
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password BLOB
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ================= GLOBAL STORAGE =================
# We avoid global variables for user-specific data to prevent privacy leaks.
# Each user will have their own folder in 'uploads/'.

# ================= ROUTES =================
@app.route("/")
def index():
    user = session.get("user")
    social_success = request.args.get("social_success")
    print(f"DEBUG: Index access. Session user: {user}, Social Success: {social_success}")
    
    if user and not social_success:
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

    conn = sqlite3.connect("users.db", timeout=10)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )
        conn.commit()
        return jsonify({"message": "User Registered Successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "Email already exists"}), 400
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# ================= SIGN IN =================
@app.route("/signin", methods=["POST"])
def signin():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    conn = sqlite3.connect("users.db", timeout=10)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password.encode("utf-8"), user[0]):
            session["user"] = email
            return jsonify({"message": "Login Successful"})
        else:
            return jsonify({"message": "Invalid Credentials"}), 400
    finally:
        conn.close()

# ================= FORGOT PASSWORD =================
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    conn = sqlite3.connect("users.db", timeout=10)
    try:
        cursor = conn.cursor()
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

http://localhost:5000/?mode=reset&email={email}

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

    conn = sqlite3.connect("users.db", timeout=10)
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

# ================= SOCIAL LOGIN ROUTES =================

def handle_social_login(email, name, provider, mode="signin"):
    if not email:
        # Fallback if provider doesn't return email
        email = f"{provider}_user_{name.replace(' ', '_').lower()}@example.com"
        
    conn = sqlite3.connect("users.db", timeout=10)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, f"{provider}_oauth".encode("utf-8"))
            )
            conn.commit()

        session["user"] = email
        session.permanent = True
        session.modified = True
        
        # Explicitly save session before redirecting
        print(f"DEBUG: Social Login Success for {email}. Session ID before redirect: {session.get('user')}")
        return redirect(f"/?social_success=true&mode={mode}&provider={provider}")
    finally:
        conn.close()

@app.route("/google_login")
def google_login():
    mode = request.args.get("mode", "signin")
    print(f"DEBUG: Initializing Google Login. Mode: {mode}")
    
    # Force fresh login by clearing session tokens directly
    session.pop('google_oauth_token', None)
            
    return redirect(url_for("google.login", next=url_for("google_login_callback", mode=mode), prompt="select_account"))

@app.route("/google_login_callback")
def google_login_callback():
    mode = request.args.get("mode", "signin")
    if not google.authorized:
        return redirect(url_for("google.login", next=url_for("google_login_callback", mode=mode), prompt="select_account"))
    
    try:
        print("DEBUG: Google Authorized. Fetching user info...")
        resp = google.get("/oauth2/v2/userinfo")
        
        if not resp.ok:
            print(f"DEBUG: Google fetch failed. Status: {resp.status_code}, Body: {resp.text}")
            # If the token is invalid/expired, clear it and try again
            if resp.status_code == 401:
                del app.blueprints['google'].token
                return redirect(url_for("google_login", mode=mode))
            return f"Failed to fetch user info from Google: {resp.text}", 400
            
        user_info = resp.json()
        print(f"DEBUG: Google Info Received: {user_info.get('email')}")
        return handle_social_login(user_info["email"], user_info.get("name", "Google User"), "google", mode=mode)
    except Exception as e:
        print(f"DEBUG: Google Exception: {str(e)}")
        # Clear token on any oauth error to force a fresh login next time
        if "token_expired" in str(e).lower() or "expired" in str(e).lower():
            del app.blueprints['google'].token
            return redirect(url_for("google_login", mode=mode))
        return f"Social Login Error: {str(e)}", 500

@app.route("/facebook_login")
def facebook_login():
    mode = request.args.get("mode", "signin")
    print(f"DEBUG: Starting Facebook Login. Mode: {mode}")
    
    if 'facebook' in app.blueprints:
        try:
            del app.blueprints['facebook'].token
        except:
            pass
            
    return redirect(url_for("facebook.login", next=url_for("facebook_login_callback", mode=mode), auth_type="reauthenticate"))

@app.route("/facebook_login_callback")
def facebook_login_callback():
    mode = request.args.get("mode", "signin")
    if not facebook.authorized:
        return redirect(url_for("facebook.login", next=url_for("facebook_login_callback", mode=mode), auth_type="reauthenticate"))
    
    try:
        print("DEBUG: Facebook Authorized. Fetching user info...")
        resp = facebook.get("/me?fields=id,name,email")
        
        if not resp.ok:
            print(f"DEBUG: Facebook fetch failed. Status: {resp.status_code}, Body: {resp.text}")
            if resp.status_code == 401:
                del app.blueprints['facebook'].token
                return redirect(url_for("facebook_login", mode=mode))
            return f"Failed to fetch user info from Facebook: {resp.text}", 400
            
        user_info = resp.json()
        print(f"DEBUG: Facebook Info Received: {user_info.get('email')}")
        return handle_social_login(user_info.get("email"), user_info.get("name", "Facebook User"), "facebook", mode=mode)
    except Exception as e:
        print(f"DEBUG: Facebook Exception: {str(e)}")
        if "token_expired" in str(e).lower() or "expired" in str(e).lower():
            del app.blueprints['facebook'].token
            return redirect(url_for("facebook_login", mode=mode))
        return f"Social Login Error: {str(e)}", 500

@app.route("/linkedin_login")
def linkedin_login():
    mode = request.args.get("mode", "signin")
    print(f"DEBUG: Starting LinkedIn Login. Mode: {mode}")
    
    if 'linkedin' in app.blueprints:
        try:
            del app.blueprints['linkedin'].token
        except:
            pass
            
    return redirect(url_for("linkedin.login", next=url_for("linkedin_login_callback", mode=mode), prompt="login"))

@app.route("/linkedin_login_callback")
def linkedin_login_callback():
    mode = request.args.get("mode", "signin")
    if not linkedin.authorized:
        return redirect(url_for("linkedin.login", next=url_for("linkedin_login_callback", mode=mode), prompt="login"))
    
    try:
        print("DEBUG: LinkedIn Authorized. Fetching user info...")
        resp = linkedin.get("userinfo")
        
        if not resp.ok:
            print(f"DEBUG: LinkedIn fetch failed. Status: {resp.status_code}, Body: {resp.text}")
            if resp.status_code == 401:
                del app.blueprints['linkedin'].token
                return redirect(url_for("linkedin_login", mode=mode))
            return f"Failed to fetch user info from LinkedIn: {resp.text}", 400
            
        user_info = resp.json()
        email = user_info.get("email")
        name = user_info.get("name", "LinkedIn User")
        print(f"DEBUG: LinkedIn Info Received: {email}")
        
        return handle_social_login(email, name, "linkedin", mode=mode)
    except Exception as e:
        print(f"DEBUG: LinkedIn Exception: {str(e)}")
        if "token_expired" in str(e).lower() or "expired" in str(e).lower():
            del app.blueprints['linkedin'].token
            return redirect(url_for("linkedin_login", mode=mode))
        return f"Social Login Error: {str(e)}", 500

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
