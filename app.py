import os
import sqlite3
import uuid
import secrets
import hashlib
import time
import smtplib
import ssl

from dotenv import load_dotenv
from email.message import EmailMessage
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import ChoiceLoader, FileSystemLoader
from werkzeug.utils import secure_filename

# Load credentials from the .env file
load_dotenv()


# ==================== BASIC SETUP ====================

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
DB_PATH = BASE_DIR / "crime_reporting.db"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "Templates_user"),
    static_folder=str(BASE_DIR / "static")
)

app.jinja_loader = ChoiceLoader([
    FileSystemLoader(str(BASE_DIR / "Templates_user")),
    FileSystemLoader(str(BASE_DIR / "Admin_Template")),
])


app.secret_key = os.environ.get(
    "DCRS_SECRET_KEY",
    "change-this-secret-key-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "").strip()
SMTP_APP_PASSWORD = os.environ.get(
    "SMTP_APP_PASSWORD", ""
).replace(" ", "").strip()

print("SMTP EMAIL SET:", bool(SMTP_EMAIL))
print("SMTP APP PASSWORD SET:", bool(SMTP_APP_PASSWORD))

OTP_LIFETIME_SECONDS = 300
OTP_MAX_ATTEMPTS = 5


# ==================== DATABASE ====================

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                mobile TEXT,
                password TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                mobile TEXT,
                crime_type TEXT NOT NULL,
                location TEXT NOT NULL,
                crime_date TEXT,
                crime_time TEXT,
                description TEXT NOT NULL,
                photo TEXT,
                status TEXT DEFAULT 'Pending',
                assigned_level TEXT DEFAULT 'Not Assigned',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


# ==================== OTP HELPERS ====================

def normalize_mobile(mobile):
    mobile = (
        (mobile or "")
        .strip()
        .replace(" ", "")
        .replace("-", "")
    )

    if mobile.startswith("+91"):
        digits = mobile[3:]
    elif mobile.startswith("91") and len(mobile) == 12:
        digits = mobile[2:]
    else:
        digits = mobile

    if (
        len(digits) == 10
        and digits.isdigit()
        and digits[0] in "6789"
    ):
        return "+91" + digits

    return None


def otp_hash(otp):
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


def create_otp():
    return f"{secrets.randbelow(1000000):06d}"


def clear_otp(prefix):
    for key in ("target", "hash", "expires", "attempts"):
        session.pop(f"{prefix}_{key}", None)


def otp_is_valid(prefix, otp, target):
    if not otp or not otp.isdigit() or len(otp) != 6:
        return False, "Enter the 6-digit OTP."

    saved_target = session.get(f"{prefix}_target")
    saved_hash = session.get(f"{prefix}_hash")
    expires_at = session.get(f"{prefix}_expires", 0)
    attempts = session.get(f"{prefix}_attempts", 0)

    if (
        not saved_target
        or saved_target != target
        or not saved_hash
    ):
        return False, "Request a new OTP first."

    if time.time() > expires_at:
        clear_otp(prefix)
        return False, "OTP expired. Request a new OTP."

    if attempts >= OTP_MAX_ATTEMPTS:
        clear_otp(prefix)
        return False, "Too many attempts. Request a new OTP."

    session[f"{prefix}_attempts"] = attempts + 1

    if secrets.compare_digest(otp_hash(otp), saved_hash):
        return True, "OTP verified successfully."

    return False, "Incorrect OTP. Try again."


# ==================== SEND EMAIL OTP ====================

def send_email_otp(to_email, otp):
    if not SMTP_EMAIL or not SMTP_APP_PASSWORD:
        raise RuntimeError(
            "Email OTP is not configured. Set SMTP_EMAIL "
            "and SMTP_APP_PASSWORD in PowerShell."
        )

    message = EmailMessage()
    message["Subject"] = "Your DCRS signup verification code"
    message["From"] = SMTP_EMAIL
    message["To"] = to_email

    message.set_content(
        f"Your DCRS verification code is: {otp}\n\n"
        f"This code expires in "
        f"{OTP_LIFETIME_SECONDS // 60} minutes.\n"
        "Do not share this code with anyone."
    )

    # Try Gmail SMTP port 587 first.
    try:
        with smtplib.SMTP(
            "smtp.gmail.com", 587, timeout=30
        ) as server:
            server.ehlo()
            server.starttls(
                context=ssl.create_default_context()
            )
            server.ehlo()
            server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            server.send_message(message)

    except (
        smtplib.SMTPServerDisconnected,
        TimeoutError,
        OSError
    ):
        # Retry using Gmail SSL port 465.
        app.logger.warning(
            "Port 587 disconnected; retrying on port 465."
        )

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            timeout=30,
            context=ssl.create_default_context()
        ) as server:
            server.login(SMTP_EMAIL, SMTP_APP_PASSWORD)
            server.send_message(message)


# ==================== LOGIN PROTECTION ====================

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ==================== HOME ====================


@app.route("/")
def role_selection():
    return render_template("Role_finder.html")


@app.route("/index")
def index():
    return render_template("Index.html")


@app.route("/admin-index")
def admin_index():
    return render_template("Admin_Index.html")


# ==================== SEND PHONE DEMO OTP ====================

# ==================== SEND PHONE DEMO OTP ====================

@app.route("/send-signup-otp", methods=["POST"])
def send_signup_otp():
    data = request.get_json(silent=True) or request.form
    mobile = normalize_mobile(data.get("mobile"))

    if not mobile:
        return jsonify(
            success=False,
            error="Enter a valid Indian mobile number."
        ), 400

    otp = create_otp()

    clear_otp("signup_phone")
    session.pop("signup_verified_mobile", None)

    session["signup_phone_target"] = mobile
    session["signup_phone_hash"] = otp_hash(otp)
    session["signup_phone_expires"] = (
        time.time() + OTP_LIFETIME_SECONDS
    )
    session["signup_phone_attempts"] = 0

    # DEMO OTP: no real SMS is sent.
    return jsonify(
        success=True,
        message=(
            f"DEMO MOBILE OTP: {otp}. "
            "No SMS was sent. "
            "OTP expires in 5 minutes."
        ),
        demo_otp=otp,
        expires_in=OTP_LIFETIME_SECONDS
    )

# ==================== VERIFY PHONE DEMO OTP ====================

@app.route("/verify-signup-otp", methods=["POST"])
def verify_signup_otp():
    data = request.get_json(silent=True) or request.form

    mobile = normalize_mobile(data.get("mobile"))
    otp = (data.get("otp") or "").strip()

    if not mobile:
        return jsonify(
            error="Enter a valid Indian mobile number."
        ), 400

    if session.get("signup_phone_target") != mobile:
        session.pop("signup_verified_mobile", None)
        return jsonify(
            error="Request a demo OTP for this number first."
        ), 400

    valid, message = otp_is_valid(
        "signup_phone", otp, mobile
    )

    if not valid:
        session.pop("signup_verified_mobile", None)
        return jsonify(error=message), 400

    session["signup_verified_mobile"] = mobile
    clear_otp("signup_phone")

    return jsonify(
        message=(
            "Demo phone OTP verified. "
            "This does not prove phone ownership."
        )
    )


# ==================== SEND REAL EMAIL OTP ====================

@app.route("/send-signup-email-otp", methods=["POST"])
def send_signup_email_otp():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()

    if (
        not email
        or "@" not in email
        or "." not in email.rsplit("@", 1)[-1]
    ):
        return jsonify(
            error="Enter a valid email address."
        ), 400

    otp = create_otp()

    clear_otp("signup_email")
    session.pop("signup_verified_email", None)

    try:
        send_email_otp(email, otp)

    except RuntimeError as exc:
        app.logger.error("SMTP configuration error: %s", exc)
        return jsonify(error=str(exc)), 503

    except smtplib.SMTPAuthenticationError:
        app.logger.exception("Gmail SMTP authentication failed")
        return jsonify(
            error=(
                "Gmail login failed. Check your Gmail address "
                "and Google App Password."
            )
        ), 502

    except (
        smtplib.SMTPException,
        OSError,
        TimeoutError
    ):
        app.logger.exception("Email OTP delivery failed")
        return jsonify(
            error=(
                "Could not send email OTP. Check the Flask "
                "terminal for the SMTP error."
            )
        ), 502

    except Exception:
        app.logger.exception("Unexpected email OTP error")
        return jsonify(
            error=(
                "Could not send email OTP. Check the Flask "
                "terminal for details."
            )
        ), 502

    # Store OTP only after the email is sent successfully.
    session["signup_email_target"] = email
    session["signup_email_hash"] = otp_hash(otp)
    session["signup_email_expires"] = (
        time.time() + OTP_LIFETIME_SECONDS
    )
    session["signup_email_attempts"] = 0

    return jsonify(
        message="OTP sent to your email. Check Inbox and Spam.",
        expires_in=OTP_LIFETIME_SECONDS
    )


# ==================== VERIFY EMAIL OTP ====================

@app.route("/verify-signup-email-otp", methods=["POST"])
def verify_signup_email_otp():
    data = request.get_json(silent=True) or request.form

    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    if (
        not email
        or "@" not in email
        or "." not in email.rsplit("@", 1)[-1]
    ):
        return jsonify(
            error="Enter a valid email address."
        ), 400

    if session.get("signup_email_target") != email:
        session.pop("signup_verified_email", None)
        return jsonify(
            error="Request an email OTP for this address first."
        ), 400

    valid, message = otp_is_valid(
        "signup_email", otp, email
    )

    if not valid:
        session.pop("signup_verified_email", None)
        return jsonify(error=message), 400

    session["signup_verified_email"] = email
    clear_otp("signup_email")

    return jsonify(
        message="Email verified successfully."
    )


# ==================== SIGNUP ====================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")

        confirm_password = (
            request.form.get("confirm_password")
            or request.form.get("confirmPassword")
            or ""
        )

        normalized_mobile = normalize_mobile(mobile)

        if not all([name, email, mobile, password]):
            flash("Please fill all required fields.", "error")
            return redirect(url_for("signup"))

        if (
            not email
            or "@" not in email
            or "." not in email.rsplit("@", 1)[-1]
        ):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("signup"))

        if not normalized_mobile:
            flash("Enter a valid Indian mobile number.", "error")
            return redirect(url_for("signup"))

        if (
            session.get("signup_verified_mobile")
            != normalized_mobile
        ):
            flash(
                "Verify the phone demo OTP first.",
                "error"
            )
            return redirect(url_for("signup"))

        if session.get("signup_verified_email") != email:
            flash(
                "Verify your email using OTP first.",
                "error"
            )
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("signup"))

        try:
            with get_db() as db:
                cursor = db.execute("""
                    INSERT INTO users
                        (name, email, mobile, password)
                    VALUES (?, ?, ?, ?)
                """, (
                    name,
                    email,
                    normalized_mobile,
                    generate_password_hash(password)
                ))

                user = db.execute("""
                    SELECT id, name, email
                    FROM users
                    WHERE id = ?
                """, (cursor.lastrowid,)).fetchone()

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["role"] = "citizen"

            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))

        except sqlite3.IntegrityError:
            flash(
                "This email is already registered.",
                "error"
            )
            return redirect(url_for("signup"))

    return render_template("Signup.html")


# ==================== LOGIN ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (
            request.form.get("email")
            or request.form.get("username")
            or ""
        ).strip().lower()

        password = (
            request.form.get("password")
            or request.form.get("loginpassword")
            or ""
        )

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(
            user["password"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["role"] = "citizen"

            
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    return render_template("Login.html")


# ==================== DASHBOARD ====================

@app.route("/dashboard")
@app.route("/portal")
@login_required
def dashboard():
    with get_db() as db:
        complaints = db.execute("""
            SELECT complaint_id, crime_type, status, created_at
            FROM complaints
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 5
        """, (session["user_id"],)).fetchall()

        total_complaints = db.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE user_id = ?
        """, (session["user_id"],)).fetchone()[0]

    return render_template(
        "Dashboard.html",
        complaints=complaints,
        recent_complaints=complaints,
        total_complaints=total_complaints,
        user_name=session.get("user_name"),
        user_email=session.get("user_email")
    )



# ==================== REPORT CRIME OTP ====================

@app.route("/report/send-email-otp", methods=["POST"])
@login_required
def report_send_email_otp():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()

    if (
        not email
        or "@" not in email
        or "." not in email.rsplit("@", 1)[-1]
    ):
        return jsonify(
            success=False,
            message="Enter a valid email address."
        ), 400

    clear_otp("report_email")
    session.pop("report_email_verified", None)

    otp = create_otp()

    try:
        send_email_otp(email, otp)
    except Exception:
        app.logger.exception("Report email OTP failed")
        return jsonify(
            success=False,
            message="Email OTP could not be sent. Check SMTP settings."
        ), 500

    session["report_email_target"] = email
    session["report_email_hash"] = otp_hash(otp)
    session["report_email_expires"] = (
        time.time() + OTP_LIFETIME_SECONDS
    )
    session["report_email_attempts"] = 0

    return jsonify(
        success=True,
        message="OTP sent to your email. Check Inbox and Spam.",
        expires_in=OTP_LIFETIME_SECONDS
    )


# ==================== REPORT MOBILE DEMO OTP ====================

@app.route("/report/send-mobile-otp", methods=["POST"])
@login_required
def report_send_mobile_otp():
    data = request.get_json(silent=True) or request.form
    mobile = (data.get("mobile") or "").strip()

    if not mobile:
        return jsonify(
            success=False,
            message="Enter your mobile number."
        ), 400

    clear_otp("report_mobile")
    session.pop("report_mobile_verified", None)

    otp = create_otp()

    session["report_mobile_target"] = mobile
    session["report_mobile_hash"] = otp_hash(otp)
    session["report_mobile_expires"] = (
        time.time() + OTP_LIFETIME_SECONDS
    )
    session["report_mobile_attempts"] = 0

    # Demo only: no real SMS is sent.
    return jsonify(
        success=True,
        message="Demo OTP generated. No SMS was sent.",
        demo_otp=otp,
        expires_in=OTP_LIFETIME_SECONDS
    )


# ==================== VERIFY REPORT OTP ====================

@app.route("/report/verify-otp", methods=["POST"])
@login_required
def report_verify_otp():
    data = request.get_json(silent=True) or request.form

    kind = (data.get("kind") or "").strip()
    otp = (data.get("otp") or "").strip()
    destination = (data.get("destination") or "").strip()

    if kind not in ("email", "mobile"):
        return jsonify(
            success=False,
            message="Invalid OTP type."
        ), 400

    if kind == "email":
        destination = destination.lower()

    prefix = f"report_{kind}"

    if session.get(f"{prefix}_target") != destination:
        session.pop(f"{prefix}_verified", None)
        return jsonify(
            success=False,
            message="Request a new OTP for these details."
        ), 400

    valid, message = otp_is_valid(
        prefix, otp, destination
    )

    if not valid:
        session.pop(f"{prefix}_verified", None)
        return jsonify(
            success=False,
            message=message
        ), 400

    session[f"{prefix}_verified"] = True

    return jsonify(
        success=True,
        message="OTP verified successfully."
    )


# ==================== REPORT CRIME ====================

@app.route("/report", methods=["GET", "POST"])
@login_required
def report_crime():

    if request.method == "GET":
        return render_template("Report_crime.html")

    # 1. Read form fields
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    mobile = request.form.get("mobile", "").strip()
    crime_type = request.form.get("crime_type", "").strip()
    location = request.form.get("location", "").strip()
    crime_date = request.form.get("crime_date", "").strip()
    crime_time = request.form.get("crime_time", "").strip()
    description = request.form.get("description", "").strip()

    # 2. Validate required fields
    if not all([
        full_name, email, mobile,
        crime_type, location, description
    ]):
        flash("Please fill all required complaint fields.", "error")
        return redirect(url_for("report_crime"))

    # 3. Both OTPs must be verified
    if not session.get("report_email_verified"):
        flash("Please verify your email OTP first.", "error")
        return redirect(url_for("report_crime"))

    if not session.get("report_mobile_verified"):
        flash("Please verify your mobile demo OTP first.", "error")
        return redirect(url_for("report_crime"))

    # 4. Verify contact details match the OTP destinations
    if session.get("report_email_target") != email:
        clear_otp("report_email")
        session.pop("report_email_verified", None)
        flash("Email changed. Please verify it again.", "error")
        return redirect(url_for("report_crime"))

    if session.get("report_mobile_target") != mobile:
        clear_otp("report_mobile")
        session.pop("report_mobile_verified", None)
        flash("Mobile changed. Please verify it again.", "error")
        return redirect(url_for("report_crime"))

    # 5. Check expiry at submission time
    for kind in ("email", "mobile"):
        prefix = f"report_{kind}"
        expires = session.get(f"{prefix}_expires", 0)

        if (
            not session.get(f"{prefix}_hash")
            or time.time() > expires
        ):
            clear_otp(prefix)
            session.pop(f"{prefix}_verified", None)
            flash(
                f"Your {kind} OTP expired. Please verify again.",
                "error"
            )
            return redirect(url_for("report_crime"))

    # 6. Validate optional photo
    photo_name = None
    photo = request.files.get("photo")

    if photo and photo.filename:
        if not allowed_file(photo.filename):
            flash(
                "Upload JPG, JPEG, PNG or WEBP only.",
                "error"
            )
            return redirect(url_for("report_crime"))

        safe_name = secure_filename(photo.filename)

        if not safe_name:
            flash("Invalid photo filename.", "error")
            return redirect(url_for("report_crime"))

        photo_name = f"{uuid.uuid4().hex}_{safe_name}"

    # 7. Save complaint photo
    if photo_name and photo:
        photo.save(UPLOAD_DIR / photo_name)

    # 8. Generate complaint ID
    complaint_id = "CR-" + uuid.uuid4().hex[:10].upper()

    # 9. Insert complaint into the database
    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO complaints (
                    complaint_id, user_id, full_name, email,
                    mobile, crime_type, location, crime_date,
                    crime_time, description, photo, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
            """, (
                complaint_id,
                session["user_id"],
                full_name,
                email,
                mobile,
                crime_type,
                location,
                crime_date,
                crime_time,
                description,
                photo_name
            ))

    except Exception:
        app.logger.exception("Failed to save crime complaint")

        if photo_name:
            try:
                (UPLOAD_DIR / photo_name).unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Failed to remove uploaded photo")

        flash(
            "Complaint could not be saved. Please try again.",
            "error"
        )
        return redirect(url_for("report_crime"))

    # 10. Clear OTPs after successful submission
    clear_otp("report_email")
    clear_otp("report_mobile")
    session.pop("report_email_verified", None)
    session.pop("report_mobile_verified", None)

        # 11. Redirect to submission success page
    flash(
        f"Complaint submitted successfully. ID: {complaint_id}",
        "success"
    )

    return redirect(url_for(
        "submit_success",
        complaint_id=complaint_id
    ))

# ==================== SUBMISSION SUCCESS ====================

@app.route("/submit", endpoint="submit_success")
@login_required
def submit_success():
    complaint_id = request.args.get("complaint_id", "")

    return render_template(
        "Submit.html",
        complaint_id=complaint_id
    )

    



# ==================== MY COMPLAINTS ====================


@app.route("/my-complaints")
@login_required
def my_complaints():

    with get_db() as db:

        # Fetch all complaints of logged-in user
        complaints = db.execute("""
            SELECT *
            FROM complaints
            WHERE user_id = ?
            ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

        # Calculate complaint statistics
        total_complaints = len(complaints)

        pending_complaints = sum(
            1 for c in complaints
            if (c["status"] or "").strip().lower() == "pending"
        )

        resolved_complaints = sum(
            1 for c in complaints
            if (c["status"] or "").strip().lower() == "resolved"
        )

    return render_template(
        "My_Complaint.html",
        complaints=complaints,
        my_complaints=complaints,

        total_complaints=total_complaints,
        pending_complaints=pending_complaints,
        resolved_complaints=resolved_complaints
    )



# ==================== COMPLAINT STATUS ====================

@app.route("/complaint-status")
@login_required
def complaint_status():
    complaint_id = request.args.get("complaint_id", "").strip()

    with get_db() as db:
        # Fetch all complaints belonging to the logged-in user
        complaints = db.execute("""
            SELECT complaint_id, crime_type, crime_date,
                   status, created_at
            FROM complaints
            WHERE user_id = ?
            ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

        # Fetch the selected complaint when an ID is searched
        complaint = None
        error = None

        if complaint_id:
            complaint = db.execute("""
                SELECT *
                FROM complaints
                WHERE complaint_id = ? AND user_id = ?
            """, (
                complaint_id,
                session["user_id"]
            )).fetchone()

            if not complaint:
                error = "Complaint not found. Please check your Complaint ID."

    return render_template(
        "Complaint_Status.html",
        complaints=complaints,
        complaint=complaint,
        error=error
    )


# ==================== PROFILE ====================

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    with get_db() as db:

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            mobile = request.form.get("mobile", "").strip()

            if not name:
                flash("Name is required.", "error")
                return redirect(url_for("profile"))

            db.execute("""
                UPDATE users
                SET name = ?, mobile = ?
                WHERE id = ?
            """, (name, mobile, session["user_id"]))

            session["user_name"] = name
            flash("Profile updated successfully.", "success")
            return redirect(url_for("profile"))

        user = db.execute("""
            SELECT id, name, email, mobile
            FROM users
            WHERE id = ?
        """, (session["user_id"],)).fetchone()

    return render_template(
        "My_profile.html",
        user=user,
        profile=user
    )



# ==================== INFORMATION PAGES ====================

@app.route("/know-your-law")
def know_your_law():
    return render_template("Know_Your_Law.html")


@app.route("/about")
def about():
    return render_template("About_us.html")


# ==================== CONTACT ====================

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get(
            "email", ""
        ).strip().lower()
        subject = request.form.get(
            "subject", ""
        ).strip()
        message = request.form.get(
            "message", ""
        ).strip()

        if not all([name, email, subject, message]):
            flash(
                "Please fill all contact form fields.",
                "error"
            )
            return redirect(url_for("contact"))

        with get_db() as db:
            db.execute("""
                INSERT INTO contact_messages
                    (user_id, name, email, subject, message)
                VALUES (?, ?, ?, ?, ?)
            """, (
                session.get("user_id"),
                name,
                email,
                subject,
                message
            ))

        flash(
            "Your message has been submitted.",
            "success"
        )
        return redirect(url_for("contact"))

    return render_template("Contact_us.html")


# ==================== LOGOUT ====================

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("role_selection"))


# ==================== ERROR HANDLER ====================

@app.errorhandler(413)
def file_too_large(error):
    flash(
        "File is too large. Maximum upload size is 5 MB.",
        "error"
    )
    return redirect(url_for("report_crime"))




    # =========================================================
# ==================== ADMIN BACKEND ======================
# =========================================================

from jinja2 import ChoiceLoader, FileSystemLoader

# User aur Admin dono template folders ko support karo.
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(str(BASE_DIR / "Templates_user")),
    FileSystemLoader(str(BASE_DIR / "Admin_Template")),
])


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Admin login route ko session mein admin_id set karna hoga.
        if not session.get("admin_id") or session.get("role") != "admin":
            flash("Please login with an authorized admin account.", "error")
            return redirect(url_for("admin_login"))

        return func(*args, **kwargs)

    return wrapper


# Admin login page


# -------- ADMIN LOGIN --------

@app.route("/admin/signup", methods=["GET"])
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("Admin_signup.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    expected_username = os.environ.get("DCRS_ADMIN_USERNAME", "")
    expected_password = os.environ.get("DCRS_ADMIN_PASSWORD", "")

    if not expected_username or not expected_password:
        app.logger.error("Admin credentials are missing from .env")
        return "Admin credentials are not configured.", 500

    if (
        secrets.compare_digest(username, expected_username)
        and secrets.compare_digest(password, expected_password)
    ):
        session.clear()
        session["admin_id"] = 1
        session["admin_name"] = username
        session["name"] = username
        session["role"] = "admin"

        return redirect(url_for("admin_dashboard"))

    return render_template("Admin_signup.html"), 401


# -------- ADMIN DASHBOARD --------


# -------- ADMIN DASHBOARD --------

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    with get_db() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM complaints"
        ).fetchone()[0]

        pending = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'Pending'"
        ).fetchone()[0]

        in_progress = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'In Progress'"
        ).fetchone()[0]

        resolved = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'Resolved'"
        ).fetchone()[0]

        complaints = db.execute(
            "SELECT * FROM complaints ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "Admin_Dashboard.html",
        total_complaints=total,
        pending_complaints=pending,
        in_progress_complaints=in_progress,
        resolved_complaints=resolved,
        complaints=complaints
    )



# -------- ALL CITIZEN COMPLAINTS --------

@app.route("/admin/complaints")
@admin_required
def admin_complaints():
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "").strip()

    query = """
        SELECT
            c.id,
            c.complaint_id,
            c.full_name,
            c.email,
            c.mobile,
            c.crime_type,
            c.location,
            c.crime_date,
            c.crime_time,
            c.description,
            c.photo,
            c.status,
            c.assigned_level,
            c.created_at
        FROM complaints AS c
        WHERE 1=1
    """
    params = []

    if search:
        query += """
            AND (
                c.complaint_id LIKE ?
                OR c.full_name LIKE ?
                OR c.email LIKE ?
                OR c.crime_type LIKE ?
                OR c.location LIKE ?
            )
        """
        term = f"%{search}%"
        params.extend([term] * 5)

    allowed_statuses = {
    "Pending", "In Progress", "Resolved", "Rejected"
}

    if status in allowed_statuses:
        query += " AND c.status = ?"
        params.append(status)

    query += " ORDER BY c.id DESC"

    with get_db() as db:
        complaints = db.execute(query, params).fetchall()

        total = db.execute(
            "SELECT COUNT(*) FROM complaints"
        ).fetchone()[0]

        pending = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'Pending'"
        ).fetchone()[0]

        in_progress = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'In Progress'"
        ).fetchone()[0]

        resolved = db.execute(
            "SELECT COUNT(*) FROM complaints WHERE status = 'Resolved'"
        ).fetchone()[0]

    return render_template(
        "Admin_Complaints.html",
        complaints=complaints,
        total=total,
        pending=pending,
        in_progress=in_progress,
        resolved=resolved,
        search=search,
        selected_status=status
    )


# -------- VIEW ONE COMPLAINT --------

@app.route("/admin/complaints/<complaint_id>")
@admin_required
def admin_complaint_detail(complaint_id):
    with get_db() as db:
        complaint = db.execute("""
            SELECT *
            FROM complaints
            WHERE complaint_id = ?
        """, (complaint_id,)).fetchone()

    if not complaint:
        flash("Complaint not found.", "error")
        return redirect(url_for("admin_complaints"))

    return render_template(
        "Admin_Complaint_Detail.html",
        complaint=complaint
    )


# -------- UPDATE COMPLAINT STATUS --------

@app.route(
    "/admin/complaints/<complaint_id>/update",
    methods=["POST"]
)
@admin_required
def admin_update_complaint(complaint_id):
    status = request.form.get("status", "").strip()
    assigned_level = request.form.get(
        "assigned_level", "Not Assigned"
    ).strip()

    allowed_statuses = {
    "Pending", "In Progress", "Resolved", "Rejected"
}
    

    if status not in allowed_statuses:
        flash("Invalid complaint status.", "error")
        return redirect(url_for(
            "admin_complaint_detail",
            complaint_id=complaint_id
        ))

    with get_db() as db:
        cursor = db.execute("""
            UPDATE complaints
            SET status = ?, assigned_level = ?
            WHERE complaint_id = ?
        """, (status, assigned_level, complaint_id))

        if cursor.rowcount == 0:
            flash("Complaint not found.", "error")
            return redirect(url_for("admin_complaints"))

    flash("Complaint updated successfully.", "success")
    return redirect(url_for(
        "admin_complaint_detail",
        complaint_id=complaint_id
    ))


# ==================== ADMIN USER MANAGEMENT ====================

@app.route("/admin/users")
@admin_required
def admin_users():
    with get_db() as db:
        complaints = db.execute("""
            SELECT
                id,
                complaint_id,
                full_name,
                crime_type,
                location,
                status,
                assigned_level,
                created_at
            FROM complaints
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "Admin_Users.html",
        complaints=complaints
    )

# -------- ADMIN LOGOUT --------


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_name", None)

    if session.get("role") == "admin":
        session.pop("role", None)

    flash("Admin logged out successfully.", "success")
    return redirect(url_for("role_selection"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)