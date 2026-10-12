"""Reset the database and load demo data:  python seed.py"""
import os
import random
import sqlite3
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

import app as sms

if os.path.exists(sms.DB_PATH):
    os.remove(sms.DB_PATH)
sms.init_db()  # schema + configured initial admin

conn = sqlite3.connect(sms.DB_PATH)
conn.execute("PRAGMA foreign_keys = ON")
conn.execute("UPDATE app_metadata SET value=? WHERE key='login_tracking_started_at'",
             ((date.today() - timedelta(days=45)).isoformat() + " 12:00:00",))
if not conn.execute("SELECT 1 FROM users WHERE email='admin@college.edu' LIMIT 1").fetchone():
    conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                 ("Demo Administrator", "admin@college.edu",
                  generate_password_hash("admin123"), "admin"))
pw = generate_password_hash("password123")
random.seed(7)


def add_user(name, email, role, roll=None, dept=None):
    return conn.execute(
        "INSERT INTO users(name,email,password_hash,role,roll_no,department) VALUES(?,?,?,?,?,?)",
        (name, email, pw, role, roll, dept)).lastrowid


faculty = [add_user("Dr. Meera Rao", "meera@college.edu", "faculty", dept="Computer Science"),
           add_user("Prof. Arjun Nair", "arjun@college.edu", "faculty", dept="Computer Science")]
names = ["Aarav Sharma", "Diya Reddy", "Kabir Singh", "Ananya Iyer", "Rohan Gupta", "Sneha Patel"]
students = [add_user(n, f"{n.split()[0].lower()}@college.edu", "student",
                     f"CS21{i + 1:03d}", "Computer Science") for i, n in enumerate(names)]

courses = []
for code, title, cr, f in [("CS101", "Programming in Python", 4, 0), ("CS102", "Data Structures", 4, 0),
                           ("CS103", "Database Systems", 3, 1), ("MA101", "Discrete Mathematics", 3, 1)]:
    courses.append(conn.execute(
        "INSERT INTO courses(code,title,credits,semester,faculty_id) VALUES(?,?,?,?,?)",
        (code, title, cr, 3, faculty[f])).lastrowid)
for s in students:
    for c in courses:
        conn.execute("INSERT INTO enrollments(student_id,course_id) VALUES(?,?)", (s, c))
        for d in range(10):
            day = (date.today() - timedelta(days=d + 1)).isoformat()
            conn.execute("INSERT INTO attendance(student_id,course_id,date,present) VALUES(?,?,?,?)",
                         (s, c, day, 1 if random.random() < 0.85 else 0))
        for exam, mx in [("Midterm", 50), ("Final", 100)]:
            conn.execute("INSERT INTO results(student_id,course_id,exam,marks,max_marks) VALUES(?,?,?,?,?)",
                         (s, c, exam, round(mx * random.uniform(0.45, 0.97), 1), mx))

conn.execute("INSERT INTO materials(course_id,title,description,url) VALUES(?,?,?,?)",
             (courses[0], "Python official tutorial", "Read chapters 1-5", "https://docs.python.org/3/tutorial/"))
assignment_id = conn.execute("INSERT INTO assignments(course_id,title,description,due_date,max_marks) VALUES(?,?,?,?,?)",
                             (courses[0], "Lab 1: Functions", "Write 5 functions and explain each.",
                              (date.today() + timedelta(days=7)).isoformat(), 10)).lastrowid
past_assignment_id = conn.execute("INSERT INTO assignments(course_id,title,description,due_date,max_marks) VALUES(?,?,?,?,?)",
                                  (courses[0], "Practice lab: Loops", "Complete the earlier practice exercise.",
                                   (date.today() - timedelta(days=3)).isoformat(), 10)).lastrowid
for index in (0, 2, 3, 5):
    conn.execute("INSERT INTO submissions(assignment_id,student_id,content) VALUES(?,?,?)",
                 (past_assignment_id, students[index], "Completed lab submission."))
skill_profiles = [("Python", "Advanced"), ("SQL", "Intermediate"), ("Java", "Intermediate"),
                  ("React", "Beginner"), ("Python", "Intermediate"), ("C++", "Advanced")]
level_scores = {"Beginner": 55, "Intermediate": 68, "Advanced": 84, "Expert": 95}
for index, (student_id, (skill_name, level)) in enumerate(zip(students, skill_profiles)):
    conn.execute("""INSERT INTO skills(student_id,name,level,certification,category,assessment_score)
                    VALUES(?,?,?,?,?,?)""",
                 (student_id, skill_name, level, "Course certificate" if index % 2 == 0 else None,
                  "Technical", level_scores[level] + index))
    conn.execute("""INSERT INTO skills(student_id,name,level,category,assessment_score)
                    VALUES(?,?,?,?,?)""",
                 (student_id, "Communication", "Intermediate", "Soft", 62 + index * 4))

for index, student_id in enumerate(students):
    login_count = 2 + index * 2
    for login_index in range(login_count):
        conn.execute("INSERT INTO login_events(user_id,logged_at) VALUES(?,datetime('now',?))",
                     (student_id, f"-{login_index + 1} days"))
    conn.execute("INSERT INTO student_engagement(student_id,kind,title,activity_date) VALUES(?,?,?,?)",
                 (student_id, "Event", "Campus technology week", date.today().isoformat()))
    if index % 2 == 0:
        conn.execute("INSERT INTO student_engagement(student_id,kind,title,activity_date) VALUES(?,?,?,?)",
                     (student_id, "Club", "Coding club", date.today().isoformat()))
    if index in (1, 3, 4):
        conn.execute("INSERT INTO student_engagement(student_id,kind,title,activity_date) VALUES(?,?,?,?)",
                     (student_id, "Hackathon", "Inter-college buildathon", date.today().isoformat()))
    if index >= 2:
        conn.execute("INSERT INTO student_engagement(student_id,kind,title,activity_date) VALUES(?,?,?,?)",
                     (student_id, "Certification", "Cloud foundations", date.today().isoformat()))

    conn.execute("""INSERT INTO placement_assessments(
                    student_id,assessed_by,aptitude_score,coding_score,mock_interview_score)
                    VALUES(?,?,?,?,?)""",
                 (student_id, faculty[index % len(faculty)], 48 + index * 8,
                  42 + index * 9, 45 + index * 8))
    feedback_course = courses[0 if index % 2 == 0 else 2]
    feedback_faculty = faculty[0 if index % 2 == 0 else 1]
    conn.execute("INSERT INTO feedback(student_id,course_id,rating,comments) VALUES(?,?,?,?)",
                 (student_id, feedback_course, [5, 4, 3, 2, 5, 3][index], "Term feedback"))
    conn.execute("""INSERT INTO faculty_feedback(student_id,faculty_id,course_id,rating,comments)
                    VALUES(?,?,?,?,?)""",
                 (student_id, feedback_faculty, feedback_course, [4, 3, 5, 2, 4, 3][index],
                  "Advisory progress note"))
for company, role, pkg in [("Infosys", "Systems Engineer", "4.5 LPA"), ("Zoho", "Software Developer", "8 LPA")]:
    conn.execute("INSERT INTO jobs(company,role,package,eligibility,description,deadline) VALUES(?,?,?,?,?,?)",
                 (company, role, pkg, "CGPA 6.0+", "On-campus drive",
                  (date.today() + timedelta(days=21)).isoformat()))
conn.execute("INSERT INTO applications(job_id,student_id,status) VALUES(1,?,?)", (students[0], "Shortlisted"))
conn.execute("INSERT INTO feedback(student_id,course_id,rating,comments,anonymous) VALUES(?,?,?,?,?)",
             (students[1], courses[0], 5, "Very clear explanations.", 1))
conn.commit()
conn.close()
print("Demo data loaded.\n  admin@college.edu / admin123\n  meera@college.edu / password123 (faculty)"
      "\n  aarav@college.edu / password123 (student)")
