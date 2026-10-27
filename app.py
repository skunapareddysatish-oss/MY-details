import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_from_directory, url_for
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_required,
    login_user, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


DATA_DIR = Path(os.environ.get("DATA_DIR", "./data")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("Set a strong SECRET_KEY environment variable.")

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "template")
)
app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DATA_DIR / 'app.sqlite3'}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25 MB per request
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

MAX_USERS = 10
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp",
    "pdf", "doc", "docx", "txt", "rtf",
    "xls", "xlsx", "ppt", "pptx", "csv", "zip",
}


# Enable SQLite foreign-key checks.
@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(connection, _record):
    if connection.__class__.__module__ == "sqlite3":
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    entries = db.relationship(
        "Entry", backref="owner", cascade="all, delete-orphan"
    )


class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    attachments = db.relationship(
        "Attachment", backref="entry", cascade="all, delete-orphan"
    )


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("entry.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def valid_username(value):
    return bool(re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", value or ""))


def seed_admin():
    """Create the first admin on the first launch, using environment variables."""
    if User.query.count() == 0:
        username = os.environ.get("ADMIN_USERNAME", "").strip().lower()
        password = os.environ.get("ADMIN_PASSWORD", "")
        if not valid_username(username) or len(password) < 12:
            raise RuntimeError(
                "On first launch, set ADMIN_USERNAME (3–32 letters/numbers) "
                "and ADMIN_PASSWORD (at least 12 characters)."
            )
        db.session.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            is_admin=True,
        ))
        db.session.commit()
    elif User.query.filter_by(is_admin=True).first() is None:
        raise RuntimeError("No admin account exists; contact the site administrator.")


with app.app_context():
    db.create_all()
    seed_admin()


@app.route("/", methods=["GET", "POST"])
@login_required
def entries():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        details = request.form.get("details", "").strip()
        files = [
            f for f in request.files.getlist("files")
            if f and f.filename
        ]

        if not title or len(title) > 120:
            flash("Enter a title of 1–120 characters.")
            return redirect(url_for("entries"))

        # Validate every filename before saving any files.
        for file in files:
            safe_name = secure_filename(file.filename)
            extension = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
            if not safe_name or extension not in ALLOWED_EXTENSIONS:
                flash(f"That file type is not allowed: {file.filename}")
                return redirect(url_for("entries"))

        entry = Entry(
            owner=current_user,
            title=title,
            details=details,
        )
        db.session.add(entry)
        db.session.flush()

        saved_paths = []
        total_size = 0
        try:
            for file in files:
                original_name = secure_filename(file.filename)[:255]
                extension = original_name.rsplit(".", 1)[-1].lower()
                stored_name = f"{uuid.uuid4().hex}.{extension}"
                destination = UPLOAD_DIR / stored_name
                file.save(destination)
                saved_paths.append(destination)
                size = destination.stat().st_size
                total_size += size

                if total_size > 24 * 1024 * 1024:
                    raise ValueError("Attachments must total less than 24 MB.")

                db.session.add(Attachment(
                    entry=entry,
                    filename=original_name,
                    stored_name=stored_name,
                    size=size,
                ))

            db.session.commit()
            flash("Information saved.")
        except Exception as error:
            db.session.rollback()
            for path in saved_paths:
                path.unlink(missing_ok=True)
            flash(str(error) if isinstance(error, ValueError) else "Could not save the entry.")
        return redirect(url_for("entries"))

    query = request.args.get("q", "").strip()
    records = Entry.query.filter_by(user_id=current_user.id).order_by(
        Entry.created_at.desc()
    ).all()
    if query:
        query_lower = query.lower()
        records = [
            entry for entry in records
            if query_lower in entry.title.lower()
            or query_lower in entry.details.lower()
            or any(query_lower in file.filename.lower() for file in entry.attachments)
        ]
    return render_template("entries.html", entries=records, query=query)


@app.post("/entries/<int:entry_id>/delete")
@login_required
def delete_entry(entry_id):
    entry = Entry.query.filter_by(
        id=entry_id, user_id=current_user.id
    ).first_or_404()

    for attachment in entry.attachments:
        (UPLOAD_DIR / attachment.stored_name).unlink(missing_ok=True)

    db.session.delete(entry)
    db.session.commit()
    flash("Entry and its attachments deleted.")
    return redirect(url_for("entries"))


@app.get("/attachments/<int:attachment_id>")
@login_required
def download_attachment(attachment_id):
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment or attachment.entry.user_id != current_user.id:
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        attachment.stored_name,
        as_attachment=True,
        download_name=attachment.filename,
        max_age=0,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("entries"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("entries"))

        flash("Incorrect username or password.")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.get("/users")
@login_required
def users():
    if not current_user.is_admin:
        abort(403)
    return render_template("users.html", users=User.query.order_by(User.username).all())


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def new_user():
    if not current_user.is_admin:
        abort(403)

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not valid_username(username):
            flash("Username must be 3–32 characters: letters, numbers, dot, dash, underscore.")
        elif len(password) < 12:
            flash("Password must be at least 12 characters.")
        elif User.query.count() >= MAX_USERS:
            flash("The 10-account limit has been reached.")
        elif User.query.filter_by(username=username).first():
            flash("That username is already in use.")
        else:
            db.session.add(User(
                username=username,
                password_hash=generate_password_hash(password),
                is_admin=False,
            ))
            db.session.commit()
            flash(f"Account created for {username}.")
            return redirect(url_for("users"))

    return render_template("new_user.html")
