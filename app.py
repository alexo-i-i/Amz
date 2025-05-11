from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# Database setup (SQLite for dev, PostgreSQL for Render)
if os.getenv("RENDER"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")  # Render PostgreSQL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"     # Local SQLite

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")
        user = User.query.filter_by(phone=phone).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("Invalid phone or password.")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")
        
        if User.query.filter_by(phone=phone).first():
            flash("Phone number already registered.")
            return redirect(url_for("register"))
        
        hashed_password = generate_password_hash(password)
        new_user = User(phone=phone, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/admin")
@login_required
def admin():
    if current_user.phone != "ADMIN_PHONE_NUMBER":  # Replace with your admin phone
        return "Unauthorized", 403
    
    phone = request.args.get("phone")
    if phone:
        user = User.query.filter_by(phone=phone).first()
        return render_template("admin_user.html", user=user)
    return render_template("admin.html")

@app.route("/admin/update_balance/<int:user_id>", methods=["POST"])
@login_required
def update_balance(user_id):
    if current_user.phone != "ADMIN_PHONE_NUMBER":
        return "Unauthorized", 403
    
    new_balance = request.form.get("balance")
    user = User.query.get(user_id)
    user.balance = float(new_balance)
    db.session.commit()
    return redirect(url_for("admin"))

# Initialize DB (Run once)
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
