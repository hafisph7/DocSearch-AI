# DocSearch AI

A modern login and dashboard application integrated with Gemini AI for document interaction.

## Features
- **Modern Login/Register Interface**: Sleek UI with smooth animations.
- **AI-Powered Dashboard**: Upload PDF documents and ask questions about them.
- **Secure Authentication**: Uses bcrypt for password hashing and Flask-Dance for Google OAuth.
- **Backend**: Built with Flask and SQLite.

## How to Run Locally
1. Clone the repository.
2. Navigate to the `backend` folder.
3. Create a virtual environment: `python -m venv venv`.
4. Activate it: `.\venv\Scripts\activate` (Windows).
5. Install dependencies: `pip install flask flask-cors flask-dance bcrypt pdfplumber google-generativeai python-dotenv`.
6. Create a `.env` file in the `backend` folder with your API keys.
7. Run the server: `python app.py`.
