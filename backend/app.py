import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

from flask import Flask, request, jsonify, render_template, redirect, session
from flask_cors import CORS
from flask_dance.contrib.google import make_google_blueprint, google
import sqlite3
import bcrypt
import pdfplumber
import google.generativeai as genai
from dotenv import load_dotenv

# ================= LOAD ENV =================
load_dotenv()

# ================= FLASK APP =================
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"
CORS(app)

# ================= GEMINI SETUP =================
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-pro")

# ================= GOOGLE OAUTH =================
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
)
app.register_blueprint(google_bp, url_prefix="/login")

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
document_text = ""

# ================= ROUTES =================
@app.route("/")
def index():
    return render_template("index.html")

# ================= SIGN UP =================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, hashed_password)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User Registered Successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "Email already exists"}), 400

# ================= SIGN IN =================
@app.route("/signin", methods=["POST"])
def signin():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode("utf-8"), user[0]):
        session["user"] = email
        return jsonify({"message": "Login Successful"})
    else:
        return jsonify({"message": "Invalid Credentials"}), 400

# ================= GOOGLE LOGIN =================
@app.route("/google_login")
def google_login():
    if not google.authorized:
        return redirect("/login/google")

    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()

    email = user_info["email"]
    name = user_info.get("name", "Google User")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, b"google_oauth")
        )
        conn.commit()

    conn.close()

    session["user"] = email
    return redirect("/dashboard")

# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")


# ================= FILE UPLOAD =================
@app.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    global document_text

    if "file" not in request.files:
        return jsonify({"message": "No file uploaded"}), 400

    file = request.files["file"]
    filepath = os.path.join("uploads", file.filename)

    if not os.path.exists("uploads"):
        os.makedirs("uploads")

    file.save(filepath)

    extracted_text = ""
    with pdfplumber.open(filepath) as pdf:
        for page in pdf.pages:
            extracted_text += page.extract_text() or ""

    document_text = extracted_text
    return jsonify({"message": "File uploaded successfully"})

# ================= LIST FILES =================
@app.route("/files", methods=["GET"])
def list_files():
    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    if not os.path.exists("uploads"):
        return jsonify([])
        
    files = []
    for filename in os.listdir("uploads"):
        filepath = os.path.join("uploads", filename)
        if os.path.isfile(filepath):
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
    
    filepath = os.path.join("uploads", filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({"message": "File deleted successfully"})
    else:
        return jsonify({"message": "File not found"}), 404

# ================= ASK QUESTION =================
@app.route("/ask", methods=["POST"])
def ask_question():
    global document_text

    if "user" not in session:
        return jsonify({"answer": "Unauthorized"}), 403

    if not document_text:
        return jsonify({"answer": "Please upload a document first."})

    data = request.json
    question = data.get("question")

    prompt = f"""
    Answer the question based only on the document below.

    Document:
    {document_text[:12000]}

    Question:
    {question}
    """

    try:
        response = model.generate_content(prompt)
        return jsonify({"answer": response.text})
    except Exception:
        return jsonify({"answer": "AI Error occurred."})

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, port=5000)
