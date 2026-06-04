from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "secure_login_project_key"

# Create Database and Table
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

init_db()

# Home Route
@app.route("/")
def home():
    return redirect("/login")

# Register Route
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            return "Username must be at least 3 characters."

        if len(password) < 6:
            return "Password must be at least 6 characters."

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            return "User already exists."

        conn.close()

        return redirect("/login")

    return render_template("register.html")

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user:

            stored_password = user[2].encode("utf-8")

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password
            ):
                session["user"] = username
                return redirect("/dashboard")

        return "Invalid Username or Password."

    return render_template("login.html")

# Dashboard Route
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

# Logout Route
@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
