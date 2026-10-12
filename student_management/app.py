"""Student Management System - Flask + SQLite.

Modules: Academics, Attendance, Results, LMS, Skills, Placements, Feedback.
Roles:   admin, faculty, student.
"""
import hashlib
import math
import os
import secrets
import sqlite3
import smtplib
import ssl
import time
from datetime import date, timedelta
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import (Flask, abort, current_app, flash, g, redirect, render_template,
                   request, session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
DB_PATH = os.environ.get("SMS_DB", os.path.join(BASE_DIR, "sms.db"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    WTF_CSRF_TIME_LIMIT=3600,
)
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set SECRET_KEY in .env or the deployment environment.")
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

JOB_STATUSES = ["Applied", "Shortlisted", "Interview", "Selected", "Rejected"]
SKILL_LEVELS = ["Beginner", "Intermediate", "Advanced", "Expert"]


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def q(sql, args=(), one=False):
    cur = db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def ex(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur.lastrowid


def init_db():
    """Create tables and an initial admin when credentials are configured."""
    conn = sqlite3.connect(DB_PATH)
    with open(os.path.join(BASE_DIR, "schema.sql")) as f:
        conn.executescript(f.read())
    conn.execute("""INSERT OR IGNORE INTO app_metadata(key,value)
                    VALUES('login_tracking_started_at',CURRENT_TIMESTAMP)""")
    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "session_version" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
    skill_columns = {row[1] for row in conn.execute("PRAGMA table_info(skills)")}
    if "category" not in skill_columns:
        conn.execute("ALTER TABLE skills ADD COLUMN category TEXT NOT NULL DEFAULT 'Technical'")
    if "assessment_score" not in skill_columns:
        conn.execute("ALTER TABLE skills ADD COLUMN assessment_score REAL")
    initial_admin_email = os.environ.get("INITIAL_ADMIN_EMAIL", "").strip().lower()
    initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD", "")
    has_admin = conn.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not has_admin and initial_admin_email and initial_admin_password:
        policy_error = password_policy_error(initial_admin_password)
        if policy_error:
            conn.close()
            raise RuntimeError(f"INITIAL_ADMIN_PASSWORD is invalid: {policy_error}")
        conn.execute(
            "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
            (os.environ.get("INITIAL_ADMIN_NAME", "Campus administrator"),
             initial_admin_email, generate_password_hash(initial_admin_password), "admin"))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def current_user():
    if "user" not in g:
        uid = session.get("uid")
        user = q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None
        if user and session.get("session_version") != user["session_version"]:
            session.clear()
            user = None
        g.user = user
    return g.user


@app.context_processor
def inject_user():
    return {"me": current_user(), "today": date.today().isoformat()}


@app.before_request
def enforce_auth_entry():
    public_endpoints = {"static", "login", "signup", "forgot_password", "reset_password"}
    if request.endpoint == "static":
        return None
    user = current_user()
    if user and request.endpoint in {"login", "signup"}:
        return redirect(url_for("dashboard"))
    if user or request.endpoint in public_endpoints:
        return None
    return redirect(url_for("login"))


def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if roles and user["role"] not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def password_policy_error(password):
    if len(password) < 12:
        return "Use at least 12 characters for your password."
    if not any(char.islower() for char in password) or not any(char.isupper() for char in password):
        return "Include both uppercase and lowercase letters in your password."
    if not any(char.isdigit() for char in password):
        return "Include at least one number in your password."
    return None


def is_gmail_address(email):
    local_part, separator, domain = email.rpartition("@")
    return bool(local_part and separator and domain == "gmail.com")


def reset_token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def send_password_reset_email(email, reset_url):
    host = os.environ.get("SMTP_HOST")
    if not host:
        if current_app.debug or current_app.testing:
            current_app.logger.info("Password reset link for %s: %s", email, reset_url)
        else:
            current_app.logger.error("SMTP_HOST is not configured; reset email was not sent.")
        return

    sender = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USERNAME")
    if not sender:
        raise ValueError("Set SMTP_FROM or SMTP_USERNAME before sending reset email.")
    message = EmailMessage()
    message["Subject"] = "Reset your Campus Hub password"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        "A password reset was requested for your Campus Hub account.\n\n"
        f"Use this one-time link within 30 minutes:\n{reset_url}\n\n"
        "If you did not request this, you can ignore this message."
    )
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=ssl.create_default_context())
        username = os.environ.get("SMTP_USERNAME")
        if username:
            server.login(username, os.environ.get("SMTP_PASSWORD", ""))
        server.send_message(message)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = q("SELECT * FROM users WHERE email=?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["uid"] = user["id"]
            session["session_version"] = user["session_version"]
            session.permanent = True
            ex("INSERT INTO login_events(user_id) VALUES(?)", (user["id"],))
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        password_error = password_policy_error(password)
        if not name or not email:
            flash("Enter your name and a valid email address.", "error")
        elif not is_gmail_address(email):
            flash("Student accounts must use a Gmail address ending in @gmail.com.", "error")
        elif password_error:
            flash(password_error, "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        elif q("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            flash("An account with that email already exists.", "error")
        else:
            ex("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'student')",
               (name, email, generate_password_hash(password)))
            flash("Your student account is ready. Sign in to continue.", "ok")
            return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = q("SELECT id,email FROM users WHERE email=?", (email,), one=True)
        if user:
            token = secrets.token_urlsafe(32)
            now = int(time.time())
            ex("DELETE FROM password_reset_tokens WHERE user_id=? OR expires_at<?", (user["id"], now))
            ex("INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)",
               (user["id"], reset_token_digest(token), now + 1800))
            reset_path = url_for("reset_password", token=token)
            public_base_url = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
            if public_base_url:
                parsed_base_url = urlsplit(public_base_url)
                is_local_http = parsed_base_url.scheme == "http" and parsed_base_url.hostname in {"localhost", "127.0.0.1"}
                if not parsed_base_url.netloc or (parsed_base_url.scheme != "https" and not is_local_http):
                    current_app.logger.error("PUBLIC_BASE_URL must be HTTPS outside local development.")
                    reset_url = None
                else:
                    reset_url = public_base_url + reset_path
            elif current_app.debug or current_app.testing:
                reset_url = url_for("reset_password", token=token, _external=True)
            else:
                current_app.logger.error("PUBLIC_BASE_URL is not configured; reset email was not sent.")
                reset_url = None
            if reset_url:
                try:
                    send_password_reset_email(user["email"], reset_url)
                except (OSError, smtplib.SMTPException, ValueError):
                    current_app.logger.exception("Password reset email delivery failed.")
        flash("If an account matches that email, password reset instructions will be sent.", "ok")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    digest = reset_token_digest(token)
    reset = q("SELECT id,user_id,expires_at FROM password_reset_tokens WHERE token_hash=?",
              (digest,), one=True)
    if not reset or reset["expires_at"] < int(time.time()):
        if reset:
            ex("DELETE FROM password_reset_tokens WHERE id=?", (reset["id"],))
        return render_template("reset_password.html", token=token, invalid=True), 400
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        password_error = password_policy_error(password)
        if password_error:
            flash(password_error, "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            connection = db()
            connection.execute("""UPDATE users SET password_hash=?,session_version=session_version+1
                                  WHERE id=?""",
                               (generate_password_hash(password), reset["user_id"]))
            connection.execute("DELETE FROM password_reset_tokens WHERE user_id=?",
                               (reset["user_id"],))
            connection.commit()
            session.clear()
            flash("Your password has been updated. Sign in with the new password.", "ok")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token, invalid=False)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Shared calculations
# --------------------------------------------------------------------------
def grade_for(pct):
    for limit, letter, points in [(90, "O", 10), (80, "A+", 9), (70, "A", 8),
                                  (60, "B", 7), (50, "C", 6), (40, "D", 5)]:
        if pct >= limit:
            return letter, points
    return "F", 0


def attendance_summary(student_id):
    rows = q("""SELECT c.id, c.code, c.title, COUNT(a.id) AS total,
                       COALESCE(SUM(a.present), 0) AS present
                FROM enrollments e
                JOIN courses c ON c.id = e.course_id
                LEFT JOIN attendance a ON a.course_id = c.id AND a.student_id = e.student_id
                WHERE e.student_id = ? GROUP BY c.id ORDER BY c.code""", (student_id,))
    out = []
    for r in rows:
        pct = round(100 * r["present"] / r["total"], 1) if r["total"] else None
        out.append({**dict(r), "pct": pct})
    return out


def result_summary(student_id):
    rows = q("""SELECT c.id, c.code, c.title, c.credits, SUM(r.marks) AS got,
                       SUM(r.max_marks) AS mx
                FROM results r JOIN courses c ON c.id = r.course_id
                WHERE r.student_id = ? GROUP BY c.id ORDER BY c.code""", (student_id,))
    out, credits, points = [], 0, 0
    for r in rows:
        pct = round(100 * r["got"] / r["mx"], 1) if r["mx"] else 0
        letter, pts = grade_for(pct)
        out.append({**dict(r), "pct": pct, "grade": letter, "points": pts})
        credits += r["credits"]
        points += pts * r["credits"]
    return out, (round(points / credits, 2) if credits else 0)


def course_or_404(course_id):
    course = q("SELECT * FROM courses WHERE id=?", (course_id,), one=True)
    if not course:
        abort(404)
    return course


def can_manage(course):
    """Admins manage every course; faculty only their own."""
    u = current_user()
    return u["role"] == "admin" or (u["role"] == "faculty" and course["faculty_id"] == u["id"])


def can_access(course):
    u = current_user()
    if u["role"] == "student":
        return bool(q("SELECT 1 FROM enrollments WHERE student_id=? AND course_id=?",
                      (u["id"], course["id"]), one=True))
    return can_manage(course)


def my_courses():
    u = current_user()
    if u["role"] == "admin":
        return q("SELECT * FROM courses ORDER BY code")
    if u["role"] == "faculty":
        return q("SELECT * FROM courses WHERE faculty_id=? ORDER BY code", (u["id"],))
    return q("""SELECT c.* FROM courses c JOIN enrollments e ON e.course_id=c.id
                WHERE e.student_id=? ORDER BY c.code""", (u["id"],))


def enrolled_students(course_id):
    return q("""SELECT u.* FROM users u JOIN enrollments e ON e.student_id=u.id
                WHERE e.course_id=? ORDER BY u.roll_no, u.name""", (course_id,))


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.route("/")
@login_required()
def dashboard():
    u = current_user()
    stats = {}
    if u["role"] == "admin":
        one = lambda sql: q(sql, one=True)[0]
        stats = {
            "Students": one("SELECT COUNT(*) FROM users WHERE role='student'"),
            "Faculty": one("SELECT COUNT(*) FROM users WHERE role='faculty'"),
            "Courses": one("SELECT COUNT(*) FROM courses"),
            "Open jobs": one("SELECT COUNT(*) FROM jobs"),
            "Students placed": one("SELECT COUNT(DISTINCT student_id) FROM applications WHERE status='Selected'"),
        }
    elif u["role"] == "faculty":
        courses = my_courses()
        stats = {"My courses": len(courses),
                 "Students taught": q("""SELECT COUNT(DISTINCT e.student_id) FROM enrollments e
                        JOIN courses c ON c.id=e.course_id WHERE c.faculty_id=?""",
                                      (u["id"],), one=True)[0]}
    else:
        att = attendance_summary(u["id"])
        total = sum(a["total"] for a in att)
        present = sum(a["present"] for a in att)
        _, cgpa = result_summary(u["id"])
        pending = q("""SELECT COUNT(*) FROM assignments a
                       JOIN enrollments e ON e.course_id=a.course_id AND e.student_id=?
                       WHERE NOT EXISTS (SELECT 1 FROM submissions s
                           WHERE s.assignment_id=a.id AND s.student_id=?)""",
                    (u["id"], u["id"]), one=True)[0]
        stats = {
            "Courses enrolled": len(att),
            "Attendance": f"{round(100 * present / total, 1)}%" if total else "No data",
            "CGPA": cgpa if cgpa else "No data",
            "Pending assignments": pending,
            "Job applications": q("SELECT COUNT(*) FROM applications WHERE student_id=?",
                                  (u["id"],), one=True)[0],
        }
    return render_template("dashboard.html", stats=stats, courses=my_courses())


def weighted_score(factors):
    weight_total = sum(factor["weight"] for factor in factors)
    if not weight_total:
        return None, []
    details = []
    score = 0.0
    for factor in factors:
        effective_weight = factor["weight"] / weight_total
        contribution = factor["value"] * effective_weight
        score += contribution
        details.append({**factor, "effective_weight": round(effective_weight * 100),
                        "contribution": round(contribution, 1)})
    return round(score), details


def student_insight(student):
    student_id = student["id"]
    results, _ = result_summary(student_id)
    academic = None
    if results:
        credits = sum(row["credits"] for row in results)
        academic = round(sum(row["pct"] * row["credits"] for row in results) / credits, 1)

    attendance_rows = attendance_summary(student_id)
    attendance_total = sum(row["total"] for row in attendance_rows)
    attendance = (round(100 * sum(row["present"] for row in attendance_rows) / attendance_total, 1)
                  if attendance_total else None)

    skills = q("SELECT level,certification,category,assessment_score FROM skills WHERE student_id=?", (student_id,))
    level_points = {"Beginner": 25, "Intermediate": 50, "Advanced": 75, "Expert": 100}
    skill_score = None
    if skills:
        assessment_scores = [row["assessment_score"] for row in skills if row["assessment_score"] is not None]
        proficiency = (sum(assessment_scores) / len(assessment_scores) if assessment_scores else
                       sum(level_points.get(row["level"], 0) for row in skills) / len(skills))
        certified_ratio = sum(bool(row["certification"]) for row in skills) / len(skills)
        skill_score = round(min(100, proficiency + certified_ratio * 15), 1)

    assignment_counts = q("""SELECT COUNT(a.id) AS assigned, COUNT(s.id) AS submitted
                                                         FROM enrollments e JOIN assignments a ON a.course_id=e.course_id
                                                             AND (a.due_date IS NULL OR a.due_date <= date('now'))
                                                         LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=e.student_id
                                                         WHERE e.student_id=?""", (student_id,), one=True)
    completion = (round(100 * assignment_counts["submitted"] / assignment_counts["assigned"], 1)
                  if assignment_counts["assigned"] else None)

    login_count = q("""SELECT COUNT(*) FROM login_events WHERE user_id=?
                       AND logged_at >= datetime('now','-30 days')""", (student_id,), one=True)[0]
    login_tracking_days = q("""SELECT CAST(julianday('now')-julianday(value) AS INTEGER)
                               FROM app_metadata WHERE key='login_tracking_started_at'""", one=True)[0]
    login_window_complete = login_tracking_days >= 30
    login_score = min(100, login_count * 10) if login_window_complete else None
    engagement_rows = q("""SELECT kind,COUNT(*) AS total FROM student_engagement
                            WHERE student_id=? GROUP BY kind""", (student_id,))
    engagement_counts = {row["kind"]: row["total"] for row in engagement_rows}
    engagement_score = (min(100, engagement_counts.get("Event", 0) * 8
                            + engagement_counts.get("Club", 0) * 15
                            + engagement_counts.get("Hackathon", 0) * 20
                            + engagement_counts.get("Certification", 0) * 20)
                        if engagement_rows else None)

    placement_assessment = q("""SELECT aptitude_score,coding_score,mock_interview_score
                                 FROM placement_assessments WHERE student_id=?
                                 ORDER BY assessed_at DESC,id DESC LIMIT 1""", (student_id,), one=True)
    placement_scores = ([placement_assessment[key] for key in
                         ("aptitude_score", "coding_score", "mock_interview_score")
                         if placement_assessment[key] is not None] if placement_assessment else [])
    placement_score = round(sum(placement_scores) / len(placement_scores), 1) if placement_scores else None

    student_satisfaction = q("SELECT AVG(rating)*20 FROM feedback WHERE student_id=?",
                             (student_id,), one=True)[0]
    faculty_feedback_score = q("SELECT AVG(rating)*20 FROM faculty_feedback WHERE student_id=?",
                               (student_id,), one=True)[0]
    feedback_scores = [value for value in (student_satisfaction, faculty_feedback_score) if value is not None]
    feedback_score = round(sum(feedback_scores) / len(feedback_scores), 1) if feedback_scores else None
    backlogs = sum(row["grade"] == "F" for row in results) if results else None
    faculty_feedback_entries = q("""SELECT f.rating,f.comments,f.created_at,u.name AS faculty_name,c.code
                                    FROM faculty_feedback f JOIN users u ON u.id=f.faculty_id
                                    JOIN courses c ON c.id=f.course_id WHERE f.student_id=?
                                    ORDER BY f.created_at DESC,f.id DESC LIMIT 3""", (student_id,))

    applications = q("SELECT status FROM applications WHERE student_id=?", (student_id,))
    stage_points = {"Applied": 20, "Shortlisted": 55, "Interview": 80, "Selected": 100, "Rejected": 0}
    placement_engagement = (max(stage_points.get(row["status"], 0) for row in applications)
                            if applications else 0)

    success_factors = []
    for name, value, weight in [
        ("Academic performance", academic, 30), ("Attendance", attendance, 20),
        ("Assignment completion", completion, 10), ("LMS logins in 30 days", login_score, 5),
        ("Campus engagement", engagement_score, 10), ("Placement assessments", placement_score, 10),
        ("Skill assessment and proficiency", skill_score, 10), ("Student and faculty feedback", feedback_score, 5),
    ]:
        if value is not None:
            success_factors.append({"name": name, "value": value, "weight": weight})
    success, success_details = weighted_score(success_factors)

    readiness_factors = [{"name": "Placement application progress", "value": placement_engagement, "weight": 20}]
    if skill_score is not None:
        readiness_factors.append({"name": "Skill assessments and certifications", "value": skill_score, "weight": 35})
    if placement_score is not None:
        readiness_factors.append({"name": "Aptitude, coding, and mock interviews", "value": placement_score, "weight": 45})
    readiness, readiness_details = weighted_score(readiness_factors)

    risk_factors = []
    if academic is not None:
        risk_factors.append({"name": "Academic performance below 65", "value": max(0, (65 - academic) / 65 * 100), "weight": 20})
        risk_factors.append({"name": "Course backlogs", "value": 100 if backlogs else 0, "weight": 15})
    if attendance is not None:
        risk_factors.append({"name": "Attendance below 75%", "value": max(0, (75 - attendance) / 75 * 100), "weight": 15})
    if completion is not None:
        risk_factors.append({"name": "Assignment completion below 70", "value": max(0, (70 - completion) / 70 * 100), "weight": 10})
    if login_window_complete:
        risk_factors.append({"name": "LMS logins below 5 per month", "value": max(0, (5 - login_count) / 5 * 100), "weight": 8})
    if engagement_score is not None:
        risk_factors.append({"name": "Engagement score below 50", "value": max(0, (50 - engagement_score) / 50 * 100), "weight": 8})
    if placement_score is not None:
        risk_factors.append({"name": "Placement assessments below 55", "value": max(0, (55 - placement_score) / 55 * 100), "weight": 8})
    if skill_score is not None:
        risk_factors.append({"name": "Skill assessment below 50", "value": max(0, (50 - skill_score) / 50 * 100), "weight": 8})
    if student_satisfaction is not None:
        risk_factors.append({"name": "Student satisfaction below 60", "value": max(0, (60 - student_satisfaction) / 60 * 100), "weight": 5})
    if faculty_feedback_score is not None:
        risk_factors.append({"name": "Faculty feedback below 60", "value": max(0, (60 - faculty_feedback_score) / 60 * 100), "weight": 5})
    risk, risk_details = weighted_score(risk_factors)
    risk_band = "Insufficient data" if risk is None else "High" if risk >= 65 else "Moderate" if risk >= 35 else "Low"

    if ((academic is not None and academic < 55)
            or (attendance is not None and attendance < 65)
            or (backlogs is not None and backlogs > 0)):
        segment = "Academic support needed"
        recommendation = "Prioritize an advisor check-in and a course-level support plan."
    elif academic is not None and academic >= 75 and readiness < 55:
        segment = "Strong academics, low placement readiness"
        recommendation = "Review aptitude, coding, interview practice, and skill assessments."
    elif (completion is not None and completion < 60) or (login_window_complete and login_count < 3):
        segment = "Low LMS engagement"
        recommendation = "Check assignment progress and reconnect the student with course materials."
    elif readiness >= 70 and (success is None or success >= 60):
        segment = "Placement ready"
        recommendation = "Maintain course progress and target suitable open roles."
    elif student_satisfaction is not None and student_satisfaction < 60 or faculty_feedback_score is not None and faculty_feedback_score < 60:
        segment = "Feedback follow-up"
        recommendation = "Review student satisfaction and faculty observations with an advisor."
    elif engagement_score is None or engagement_score < 40:
        segment = "Campus engagement opportunity"
        recommendation = "Explore a club, campus event, hackathon, or certification."
    elif academic is None or not skills:
        segment = "Profile incomplete"
        recommendation = "Complete the academic and assessed-skills records."
    else:
        segment = "Balanced development"
        recommendation = "Continue steady progress and review the lowest contributing indicator."

    flags = []
    if academic is not None and academic < 65:
        flags.append("Academic average is below 65%.")
    if attendance is not None and attendance < 75:
        flags.append("Attendance is below the 75% threshold.")
    if completion is not None and completion < 70:
        flags.append("Assignment completion is below 70%.")
    if not login_window_complete:
        flags.append(f"LMS login history is building ({login_tracking_days}/30 days tracked).")
    elif login_count < 3:
        flags.append(f"Only {login_count} LMS sign-ins recorded in the last 30 days.")
    if engagement_score is None:
        flags.append("No events, clubs, hackathons, or certifications are recorded.")
    if placement_score is None:
        flags.append("Aptitude, coding, and mock interview scores are not recorded.")
    if not any(row["assessment_score"] is not None for row in skills):
        flags.append("No technical or soft-skill assessment scores are recorded.")
    if student_satisfaction is None:
        flags.append("No student satisfaction feedback is recorded.")
    if faculty_feedback_score is None:
        flags.append("No faculty feedback is recorded.")
    if backlogs:
        flags.append(f"{backlogs} course backlog(s) based on current failing grades.")

    return {
        "id": student_id, "name": student["name"], "roll_no": student["roll_no"],
        "department": student["department"], "academic": academic, "attendance": attendance,
        "readiness": readiness, "success": success, "risk": risk, "risk_band": risk_band,
        "segment": segment, "recommendation": recommendation, "risk_flags": flags,
        "success_factors": success_details, "readiness_factors": readiness_details,
        "risk_factors": risk_details, "skills_count": len(skills),
        "assignment_completion": completion, "backlogs": backlogs, "login_count": login_count,
        "login_tracking_days": login_tracking_days, "login_window_complete": login_window_complete,
        "engagement_score": engagement_score, "engagement_counts": engagement_counts,
        "placement_score": placement_score, "placement_assessment": dict(placement_assessment) if placement_assessment else None,
        "skill_score": skill_score, "has_skill_assessment": any(row["assessment_score"] is not None for row in skills),
        "skills": [dict(row) for row in skills],
        "subject_results": results, "subject_attendance": attendance_rows,
        "student_satisfaction": round(student_satisfaction, 1) if student_satisfaction is not None else None,
        "faculty_feedback_score": round(faculty_feedback_score, 1) if faculty_feedback_score is not None else None,
        "faculty_feedback_entries": [dict(row) for row in faculty_feedback_entries],
    }


@app.get("/insights")
@login_required("admin", "faculty")
def student_insights():
    user = current_user()
    if user["role"] == "admin":
        roster = q("SELECT * FROM users WHERE role='student' ORDER BY name")
    else:
        roster = q("""SELECT DISTINCT u.* FROM users u
                     JOIN enrollments e ON e.student_id=u.id
                     JOIN courses c ON c.id=e.course_id
                     WHERE u.role='student' AND c.faculty_id=? ORDER BY u.name""", (user["id"],))
    students = [student_insight(row) for row in roster]
    segment_counts = {}
    for student in students:
        segment_counts[student["segment"]] = segment_counts.get(student["segment"], 0) + 1
    search = request.args.get("q", "").strip().casefold()
    segment_filter = request.args.get("segment", "")
    filtered_students = [student for student in students
                         if (not search or search in student["name"].casefold()
                             or search in (student["roll_no"] or "").casefold())
                         and (not segment_filter or student["segment"] == segment_filter)]
    shared_courses = {}
    if user["role"] == "faculty":
        for row in q("""SELECT e.student_id,c.id,c.code FROM enrollments e
                        JOIN courses c ON c.id=e.course_id WHERE c.faculty_id=?
                        ORDER BY c.code""", (user["id"],)):
            shared_courses.setdefault(row["student_id"], []).append(dict(row))
    return render_template("insights.html", students=filtered_students,
                           segment_counts=segment_counts, search=request.args.get("q", ""),
                           segment_filter=segment_filter, shared_courses=shared_courses)


def faculty_can_assess_student(faculty_id, student_id, course_id=None):
    sql = """SELECT 1 FROM enrollments e JOIN courses c ON c.id=e.course_id
             WHERE e.student_id=? AND c.faculty_id=?"""
    params = [student_id, faculty_id]
    if course_id is not None:
        sql += " AND c.id=?"
        params.append(course_id)
    return bool(q(sql, params, one=True))


@app.post("/insights/<int:student_id>/placement-assessment")
@login_required("admin", "faculty")
def record_placement_assessment(student_id):
    user = current_user()
    student = q("SELECT id FROM users WHERE id=? AND role='student'", (student_id,), one=True)
    if not student:
        abort(404)
    if user["role"] == "faculty" and not faculty_can_assess_student(user["id"], student_id):
        abort(403)

    fields = ("aptitude_score", "coding_score", "mock_interview_score")
    scores = {}
    try:
        for field in fields:
            raw_score = request.form.get(field, "").strip()
            scores[field] = float(raw_score) if raw_score else None
            if scores[field] is not None and (not math.isfinite(scores[field]) or not 0 <= scores[field] <= 100):
                raise ValueError
    except ValueError:
        flash("Assessment scores must be between 0 and 100.", "error")
        return redirect(url_for("student_insights") + f"#student-{student_id}")
    if all(score is None for score in scores.values()):
        flash("Enter at least one placement assessment score.", "error")
        return redirect(url_for("student_insights") + f"#student-{student_id}")
    ex("""INSERT INTO placement_assessments(student_id,assessed_by,aptitude_score,coding_score,mock_interview_score)
          VALUES(?,?,?,?,?)""",
       (student_id, user["id"], scores["aptitude_score"], scores["coding_score"],
        scores["mock_interview_score"]))
    flash("Placement assessment saved.", "ok")
    return redirect(url_for("student_insights") + f"#student-{student_id}")


@app.post("/insights/<int:student_id>/faculty-feedback")
@login_required("faculty")
def record_faculty_feedback(student_id):
    student = q("SELECT id FROM users WHERE id=? AND role='student'", (student_id,), one=True)
    if not student:
        abort(404)
    try:
        course_id = int(request.form.get("course_id", ""))
        rating = int(request.form.get("rating", ""))
    except ValueError:
        abort(400)
    if not faculty_can_assess_student(current_user()["id"], student_id, course_id):
        abort(403)
    if rating < 1 or rating > 5:
        abort(400)
    comments = request.form.get("comments", "").strip()[:500]
    ex("""INSERT INTO faculty_feedback(student_id,faculty_id,course_id,rating,comments)
          VALUES(?,?,?,?,?)""",
       (student_id, current_user()["id"], course_id, rating, comments or None))
    flash("Faculty feedback saved.", "ok")
    return redirect(url_for("student_insights") + f"#student-{student_id}")


# --------------------------------------------------------------------------
# Admin: users
# --------------------------------------------------------------------------
@app.route("/users", methods=["GET", "POST"])
@login_required("admin")
def users():
    if request.method == "POST":
        f = request.form
        password = f.get("password", "")
        email = f.get("email", "").strip().lower()
        role = f.get("role", "")
        if role == "student" and not is_gmail_address(email):
            flash("Student accounts must use a Gmail address ending in @gmail.com.", "error")
            return redirect(url_for("users"))
        password_error = password_policy_error(password)
        if password_error:
            flash(password_error, "error")
            return redirect(url_for("users"))
        try:
            ex("""INSERT INTO users(name,email,password_hash,role,roll_no,department)
                  VALUES(?,?,?,?,?,?)""",
               (f["name"].strip(), email,
                generate_password_hash(password), role,
                f.get("roll_no") or None, f.get("department") or None))
            flash("User added.", "ok")
        except sqlite3.IntegrityError:
            flash("A user with this email already exists.", "error")
        return redirect(url_for("users"))
    return render_template("users.html",
                           users=q("SELECT * FROM users ORDER BY role, name"))


@app.post("/users/<int:uid>/delete")
@login_required("admin")
def delete_user(uid):
    if uid == current_user()["id"]:
        flash("You cannot delete your own account.", "error")
    else:
        ex("DELETE FROM users WHERE id=?", (uid,))
        flash("User deleted.", "ok")
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Academics: courses and enrollment
# --------------------------------------------------------------------------
@app.route("/courses", methods=["GET", "POST"])
@login_required()
def courses():
    u = current_user()
    if request.method == "POST":
        if u["role"] != "admin":
            abort(403)
        f = request.form
        try:
            ex("INSERT INTO courses(code,title,credits,semester,faculty_id) VALUES(?,?,?,?,?)",
               (f["code"].strip().upper(), f["title"].strip(), int(f["credits"]),
                int(f["semester"]), f.get("faculty_id") or None))
            flash("Course created.", "ok")
        except sqlite3.IntegrityError:
            flash("A course with this code already exists.", "error")
        return redirect(url_for("courses"))
    rows = q("""SELECT c.*, u.name AS faculty_name,
                (SELECT COUNT(*) FROM enrollments WHERE course_id=c.id) AS enrolled
                FROM courses c LEFT JOIN users u ON u.id=c.faculty_id
                ORDER BY c.semester, c.code""")
    mine = {r["id"] for r in my_courses()} if u["role"] == "student" else set()
    faculty = q("SELECT id,name FROM users WHERE role='faculty' ORDER BY name")
    return render_template("courses.html", courses=rows, mine=mine, faculty=faculty)


@app.post("/courses/<int:cid>/enroll")
@login_required("student")
def enroll(cid):
    course_or_404(cid)
    ex("INSERT OR IGNORE INTO enrollments(student_id,course_id) VALUES(?,?)",
       (current_user()["id"], cid))
    flash("Enrolled.", "ok")
    return redirect(url_for("courses"))


@app.post("/courses/<int:cid>/drop")
@login_required("student")
def drop(cid):
    ex("DELETE FROM enrollments WHERE student_id=? AND course_id=?",
       (current_user()["id"], cid))
    flash("Course dropped.", "ok")
    return redirect(url_for("courses"))


@app.post("/courses/<int:cid>/delete")
@login_required("admin")
def delete_course(cid):
    ex("DELETE FROM courses WHERE id=?", (cid,))
    flash("Course deleted.", "ok")
    return redirect(url_for("courses"))


@app.route("/courses/<int:cid>/roster", methods=["GET", "POST"])
@login_required("admin", "faculty")
def roster(cid):
    course = course_or_404(cid)
    if not can_manage(course):
        abort(403)
    if request.method == "POST" and current_user()["role"] == "admin":
        ex("INSERT OR IGNORE INTO enrollments(student_id,course_id) VALUES(?,?)",
           (int(request.form["student_id"]), cid))
        flash("Student enrolled.", "ok")
        return redirect(url_for("roster", cid=cid))
    others = q("""SELECT id,name,roll_no FROM users WHERE role='student' AND id NOT IN
                  (SELECT student_id FROM enrollments WHERE course_id=?) ORDER BY name""", (cid,))
    return render_template("roster.html", course=course,
                           students=enrolled_students(cid), others=others)


# --------------------------------------------------------------------------
# Attendance
# --------------------------------------------------------------------------
@app.route("/attendance")
@login_required()
def attendance():
    u = current_user()
    if u["role"] == "student":
        return render_template("attendance_student.html", rows=attendance_summary(u["id"]))
    return render_template("course_pick.html", title="Attendance", courses=my_courses(),
                           endpoint="mark_attendance", action="Mark attendance")


@app.route("/attendance/<int:cid>", methods=["GET", "POST"])
@login_required("admin", "faculty")
def mark_attendance(cid):
    course = course_or_404(cid)
    if not can_manage(course):
        abort(403)
    day = request.values.get("date") or date.today().isoformat()
    students = enrolled_students(cid)
    if request.method == "POST":
        present_ids = set(request.form.getlist("present"))
        for s in students:
            db().execute("""INSERT INTO attendance(student_id,course_id,date,present)
                            VALUES(?,?,?,?)
                            ON CONFLICT(student_id,course_id,date)
                            DO UPDATE SET present=excluded.present""",
                         (s["id"], cid, day, 1 if str(s["id"]) in present_ids else 0))
        db().commit()
        flash(f"Attendance saved for {day}.", "ok")
        return redirect(url_for("mark_attendance", cid=cid, date=day))
    marked = {r["student_id"]: r["present"] for r in
              q("SELECT student_id,present FROM attendance WHERE course_id=? AND date=?", (cid, day))}
    # Default to present when the date has not been recorded yet.
    status = {s["id"]: marked.get(s["id"], 1) for s in students}
    totals = {r["student_id"]: r for r in q(
        """SELECT student_id, COUNT(*) total, SUM(present) present FROM attendance
           WHERE course_id=? GROUP BY student_id""", (cid,))}
    return render_template("attendance_mark.html", course=course, students=students,
                           day=day, status=status, totals=totals)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------
@app.route("/results")
@login_required()
def results():
    u = current_user()
    if u["role"] == "student":
        summary, cgpa = result_summary(u["id"])
        detail = q("""SELECT c.code, c.title, r.exam, r.marks, r.max_marks FROM results r
                      JOIN courses c ON c.id=r.course_id WHERE r.student_id=?
                      ORDER BY c.code, r.exam""", (u["id"],))
        return render_template("results_student.html", summary=summary, cgpa=cgpa, detail=detail)
    return render_template("course_pick.html", title="Results", courses=my_courses(),
                           endpoint="enter_results", action="Enter marks")


@app.route("/results/<int:cid>", methods=["GET", "POST"])
@login_required("admin", "faculty")
def enter_results(cid):
    course = course_or_404(cid)
    if not can_manage(course):
        abort(403)
    students = enrolled_students(cid)
    if request.method == "POST":
        exam = request.form["exam"].strip()
        max_marks = float(request.form["max_marks"])
        saved = 0
        for s in students:
            raw = request.form.get(f"marks_{s['id']}", "").strip()
            if raw == "":
                continue
            marks = min(float(raw), max_marks)
            db().execute("""INSERT INTO results(student_id,course_id,exam,marks,max_marks)
                            VALUES(?,?,?,?,?)
                            ON CONFLICT(student_id,course_id,exam)
                            DO UPDATE SET marks=excluded.marks, max_marks=excluded.max_marks""",
                         (s["id"], cid, exam, marks, max_marks))
            saved += 1
        db().commit()
        flash(f"Saved marks for {saved} student(s) in {exam}.", "ok")
        return redirect(url_for("enter_results", cid=cid))
    existing = q("""SELECT u.name, u.roll_no, r.exam, r.marks, r.max_marks FROM results r
                    JOIN users u ON u.id=r.student_id WHERE r.course_id=?
                    ORDER BY r.exam, u.roll_no""", (cid,))
    return render_template("results_enter.html", course=course, students=students,
                           existing=existing)


# --------------------------------------------------------------------------
# LMS: materials, assignments, submissions
# --------------------------------------------------------------------------
@app.route("/lms")
@login_required()
def lms():
    return render_template("course_pick.html", title="Learning space", courses=my_courses(),
                           endpoint="lms_course", action="Open")


@app.route("/lms/<int:cid>")
@login_required()
def lms_course(cid):
    course = course_or_404(cid)
    if not can_access(course):
        abort(403)
    u = current_user()
    assignments = q("""SELECT a.*, s.id AS sub_id, s.grade, s.submitted_at,
                       (SELECT COUNT(*) FROM submissions WHERE assignment_id=a.id) AS sub_count
                       FROM assignments a
                       LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=?
                       WHERE a.course_id=? ORDER BY a.due_date""", (u["id"], cid))
    materials = q("SELECT * FROM materials WHERE course_id=? ORDER BY created_at DESC", (cid,))
    return render_template("lms_course.html", course=course, assignments=assignments,
                           materials=materials, manage=can_manage(course))


@app.post("/lms/<int:cid>/material")
@login_required("admin", "faculty")
def add_material(cid):
    if not can_manage(course_or_404(cid)):
        abort(403)
    f = request.form
    ex("INSERT INTO materials(course_id,title,description,url) VALUES(?,?,?,?)",
       (cid, f["title"].strip(), f.get("description"), f.get("url")))
    flash("Material added.", "ok")
    return redirect(url_for("lms_course", cid=cid))


@app.post("/lms/<int:cid>/assignment")
@login_required("admin", "faculty")
def add_assignment(cid):
    if not can_manage(course_or_404(cid)):
        abort(403)
    f = request.form
    ex("INSERT INTO assignments(course_id,title,description,due_date,max_marks) VALUES(?,?,?,?,?)",
       (cid, f["title"].strip(), f.get("description"), f.get("due_date") or None,
        int(f.get("max_marks") or 10)))
    flash("Assignment posted.", "ok")
    return redirect(url_for("lms_course", cid=cid))


@app.route("/lms/assignment/<int:aid>", methods=["GET", "POST"])
@login_required()
def assignment(aid):
    a = q("SELECT * FROM assignments WHERE id=?", (aid,), one=True)
    if not a:
        abort(404)
    course = course_or_404(a["course_id"])
    if not can_access(course):
        abort(403)
    u = current_user()
    if request.method == "POST":
        if u["role"] != "student":
            abort(403)
        ex("""INSERT INTO submissions(assignment_id,student_id,content) VALUES(?,?,?)
              ON CONFLICT(assignment_id,student_id)
              DO UPDATE SET content=excluded.content, submitted_at=CURRENT_TIMESTAMP""",
           (aid, u["id"], request.form["content"].strip()))
        flash("Submission saved.", "ok")
        return redirect(url_for("assignment", aid=aid))
    if u["role"] == "student":
        mine = q("SELECT * FROM submissions WHERE assignment_id=? AND student_id=?",
                 (aid, u["id"]), one=True)
        return render_template("assignment.html", a=a, course=course, mine=mine, subs=None)
    subs = q("""SELECT s.*, u.name, u.roll_no FROM submissions s JOIN users u ON u.id=s.student_id
                WHERE s.assignment_id=? ORDER BY u.roll_no""", (aid,))
    return render_template("assignment.html", a=a, course=course, mine=None, subs=subs)


@app.post("/lms/submission/<int:sid>/grade")
@login_required("admin", "faculty")
def grade_submission(sid):
    s = q("""SELECT s.id, s.assignment_id, a.course_id, a.max_marks FROM submissions s
             JOIN assignments a ON a.id=s.assignment_id WHERE s.id=?""", (sid,), one=True)
    if not s:
        abort(404)
    if not can_manage(course_or_404(s["course_id"])):
        abort(403)
    grade = min(float(request.form["grade"]), s["max_marks"])
    ex("UPDATE submissions SET grade=?, remarks=? WHERE id=?",
       (grade, request.form.get("remarks"), sid))
    flash("Grade saved.", "ok")
    return redirect(url_for("assignment", aid=s["assignment_id"]))


# --------------------------------------------------------------------------
# Skills
# --------------------------------------------------------------------------
@app.route("/skills", methods=["GET", "POST"])
@login_required()
def skills():
    u = current_user()
    if request.method == "POST":
        if u["role"] != "student":
            abort(403)
        f = request.form
        if f.get("record_type") == "engagement":
            kind = f.get("kind", "")
            title = f.get("title", "").strip()
            activity_date = f.get("activity_date", "")
            try:
                parsed_activity_date = date.fromisoformat(activity_date)
            except ValueError:
                parsed_activity_date = None
            if (kind not in {"Event", "Club", "Hackathon", "Certification"} or not title
                    or parsed_activity_date is None or parsed_activity_date > date.today()):
                flash("Choose a valid activity type and enter its title and date.", "error")
            else:
                ex("""INSERT INTO student_engagement(student_id,kind,title,activity_date,notes)
                      VALUES(?,?,?,?,?)""",
                   (u["id"], kind, title, activity_date, f.get("notes", "").strip() or None))
                flash("Activity added to your profile.", "ok")
            return redirect(url_for("skills"))

        category = f.get("category", "Technical")
        name = f.get("name", "").strip()
        raw_score = f.get("assessment_score", "").strip()
        try:
            assessment_score = float(raw_score) if raw_score else None
        except ValueError:
            assessment_score = None
        if (category not in {"Technical", "Soft"} or f.get("level") not in SKILL_LEVELS
            or not name or (raw_score and assessment_score is None)):
            flash("Enter a valid skill and assessment score from 0 to 100.", "error")
        elif assessment_score is not None and not 0 <= assessment_score <= 100:
            flash("Assessment scores must be between 0 and 100.", "error")
        else:
            ex("""INSERT INTO skills(student_id,name,level,certification,category,assessment_score)
                  VALUES(?,?,?,?,?,?)""",
               (u["id"], name, f["level"], f.get("certification") or None,
                category, assessment_score))
            flash("Skill added to your profile.", "ok")
        return redirect(url_for("skills"))
    if u["role"] == "student":
        rows = q("SELECT * FROM skills WHERE student_id=? ORDER BY name", (u["id"],))
        engagements = q("""SELECT * FROM student_engagement WHERE student_id=?
                           ORDER BY activity_date DESC,id DESC""", (u["id"],))
        return render_template("skills.html", rows=rows, engagements=engagements,
                               levels=SKILL_LEVELS, all_view=False)
    term = request.args.get("skill", "").strip()
    rows = q("""SELECT s.*, u.name AS student_name, u.roll_no FROM skills s
                JOIN users u ON u.id=s.student_id WHERE s.name LIKE ?
                ORDER BY s.name, u.name""", (f"%{term}%",))
    return render_template("skills.html", rows=rows, levels=SKILL_LEVELS, all_view=True, term=term)


@app.post("/skills/<int:sid>/delete")
@login_required("student")
def delete_skill(sid):
    ex("DELETE FROM skills WHERE id=? AND student_id=?", (sid, current_user()["id"]))
    return redirect(url_for("skills"))


@app.post("/engagement/<int:engagement_id>/delete")
@login_required("student")
def delete_engagement(engagement_id):
     ex("DELETE FROM student_engagement WHERE id=? AND student_id=?",
         (engagement_id, current_user()["id"]))
     flash("Activity removed from your profile.", "ok")
     return redirect(url_for("skills"))


# --------------------------------------------------------------------------
# Placements
# --------------------------------------------------------------------------
@app.route("/placements", methods=["GET", "POST"])
@login_required()
def placements():
    u = current_user()
    if request.method == "POST":
        if u["role"] != "admin":
            abort(403)
        f = request.form
        ex("""INSERT INTO jobs(company,role,package,eligibility,description,deadline)
              VALUES(?,?,?,?,?,?)""",
           (f["company"].strip(), f["role"].strip(), f.get("package"), f.get("eligibility"),
            f.get("description"), f.get("deadline") or None))
        flash("Job posted.", "ok")
        return redirect(url_for("placements"))
    jobs = q("""SELECT j.*, (SELECT COUNT(*) FROM applications WHERE job_id=j.id) AS applicants
                FROM jobs j ORDER BY j.deadline IS NULL, j.deadline""")
    mine = {}
    if u["role"] == "student":
        mine = {r["job_id"]: r["status"] for r in
                q("SELECT job_id,status FROM applications WHERE student_id=?", (u["id"],))}
    return render_template("placements.html", jobs=jobs, mine=mine)


@app.post("/placements/<int:jid>/apply")
@login_required("student")
def apply_job(jid):
    ex("INSERT OR IGNORE INTO applications(job_id,student_id) VALUES(?,?)",
       (jid, current_user()["id"]))
    flash("Application submitted.", "ok")
    return redirect(url_for("placements"))


@app.get("/placements/<int:jid>/applicants")
@login_required("admin", "faculty")
def applicants(jid):
    job = q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
    if not job:
        abort(404)
    rows = q("""SELECT a.*, u.name, u.roll_no, u.department,
                (SELECT GROUP_CONCAT(name, ', ') FROM skills WHERE student_id=u.id) AS skills
                FROM applications a JOIN users u ON u.id=a.student_id
                WHERE a.job_id=? ORDER BY a.applied_at""", (jid,))
    return render_template("applicants.html", job=job, rows=rows, statuses=JOB_STATUSES)


@app.post("/placements/application/<int:aid>/status")
@login_required("admin")
def update_application(aid):
    status = request.form["status"]
    if status not in JOB_STATUSES:
        abort(400)
    row = q("SELECT job_id FROM applications WHERE id=?", (aid,), one=True)
    if not row:
        abort(404)
    ex("UPDATE applications SET status=? WHERE id=?", (status, aid))
    flash("Status updated.", "ok")
    return redirect(url_for("applicants", jid=row["job_id"]))


@app.post("/placements/<int:jid>/delete")
@login_required("admin")
def delete_job(jid):
    ex("DELETE FROM jobs WHERE id=?", (jid,))
    flash("Job removed.", "ok")
    return redirect(url_for("placements"))


# --------------------------------------------------------------------------
# Feedback
# --------------------------------------------------------------------------
@app.route("/feedback", methods=["GET", "POST"])
@login_required()
def feedback():
    u = current_user()
    if request.method == "POST":
        if u["role"] != "student":
            abort(403)
        f = request.form
        course = course_or_404(int(f["course_id"]))
        if not can_access(course):
            abort(403)
        rating = max(1, min(5, int(f["rating"])))
        ex("INSERT INTO feedback(student_id,course_id,rating,comments,anonymous) VALUES(?,?,?,?,?)",
           (u["id"], course["id"], rating, f.get("comments"), 1 if f.get("anonymous") else 0))
        flash("Thanks, your feedback was sent.", "ok")
        return redirect(url_for("feedback"))
    if u["role"] == "student":
        mine = q("""SELECT f.*, c.code, c.title FROM feedback f JOIN courses c ON c.id=f.course_id
                    WHERE f.student_id=? ORDER BY f.created_at DESC""", (u["id"],))
        return render_template("feedback.html", courses=my_courses(), mine=mine, summary=None)
    ids = [c["id"] for c in my_courses()] or [0]
    marks = ",".join("?" * len(ids))
    summary = q(f"""SELECT c.id, c.code, c.title, COUNT(f.id) AS n, ROUND(AVG(f.rating),2) AS avg
                    FROM courses c LEFT JOIN feedback f ON f.course_id=c.id
                    WHERE c.id IN ({marks}) GROUP BY c.id ORDER BY c.code""", ids)
    comments = q(f"""SELECT f.*, c.code, u.name AS student_name FROM feedback f
                     JOIN courses c ON c.id=f.course_id JOIN users u ON u.id=f.student_id
                     WHERE f.course_id IN ({marks}) AND COALESCE(f.comments,'')<>''
                     ORDER BY f.created_at DESC LIMIT 50""", ids)
    return render_template("feedback.html", courses=[], mine=None, summary=summary,
                           comments=comments)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           msg="You don't have access to this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="That page doesn't exist."), 404


init_db()

if __name__ == "__main__":
    app.run(debug=True)
