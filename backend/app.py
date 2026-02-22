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
model = genai.GenerativeModel("models/gemini-flash-latest")

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
# We avoid global variables for user-specific data to prevent privacy leaks.
# Each user will have their own folder in 'uploads/'.

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
    You are an expert assistant. Based on the document content provided and the user's question:
    1. Provide a direct, detailed answer based ONLY on the document.
    2. Suggest 3 "Practice Resources" (Official documentation, GitHub repos, or interactive labs).
    3. Suggest 3 "Video Tutorials" (High-quality YouTube search queries or well-known educational channels).

    CRITICAL: Avoid providing specific video IDs. Instead, use search-based URLs.

    Return the response ONLY as a JSON object with this EXACT structure:
    {{
        "answer": "your answer here",
        "resources": {{
            "practice": [
                {{ "title": "Resource Title", "desc": "Short description", "link": "https://..." }}
            ],
            "videos": [
                {{ "title": "Video Title", "desc": "Short description", "link": "https://..." }}
            ]
        }}
    }}

    Document:
    {str(document_text)[:8000]}

    Question:
    {question}
    """

    try:
        response = model.generate_content(prompt)
        # Try to parse JSON from the response
        text = response.text.replace("```json", "").replace("```", "").strip()
        
        try:
            import json
            data = json.loads(text)
            # Ensure the structure matches what the frontend expects
            if "answer" not in data:
                data = {"answer": text, "resources": {"practice": [], "videos": []}}
            return jsonify(data)
        except Exception:
            # Fallback if AI didn't return valid JSON
            return jsonify({"answer": text, "resources": {"practice": [], "videos": []}})

    except Exception as e:
        return jsonify({"answer": f"AI Error occurred: {str(e)}", "resources": {"practice": [], "videos": []}})

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True, port=5000)
