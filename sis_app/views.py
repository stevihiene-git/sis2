from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from . import db
from .models import User, Student, Course, CourseRegistration, Score
from datetime import datetime
from collections import defaultdict
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# views_bp = Blueprint('views', __name__)
views_bp = Blueprint('views', __name__, template_folder='public')


def get_redirect_url():
    if not current_user.is_authenticated:
        return url_for('views.index')
    role_routes = {
        'Admin': 'views.admin_dashboard',
        'Student': 'views.student_dashboard',
        'Lecturer': 'views.lecturer_dashboard',
        'Finance': 'views.finance_dashboard'
    }
    return url_for(role_routes.get(current_user.role, 'views.index'))

def validate_admin_access():
    if current_user.role != 'Admin':
        flash('Access restricted to administrators', 'error')
        return False
    return True

def validate_student_access():
    if current_user.role != 'Student':
        flash('Access restricted to students', 'error')
        return False
    return True

def validate_lecturer_access():
    if current_user.role != 'Lecturer':
        flash('Access restricted to lecturers', 'error')
        return False
    return True


@views_bp.route('/admin/delete_course/<int:course_id>', methods=['POST'])
@login_required
def admin_delete_course(course_id):
    if not validate_admin_access():
        return redirect(get_redirect_url())

    course = db.session.get(Course, course_id)
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('views.admin_dashboard'))

    try:
        # Delete associated records
        CourseRegistration.query.filter_by(course_id=course.id).delete()
        Score.query.filter_by(course_id=course.id).delete()

        # Delete course
        db.session.delete(course)
        db.session.commit()

        flash('Course deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting course: {str(e)}")
        flash('Error deleting course. Please try again.', 'error')

    return redirect(url_for('views.admin_dashboard'))



@views_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not validate_admin_access():
        return redirect(get_redirect_url())

    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('views.admin_dashboard'))

    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('views.admin_dashboard'))

    try:
        # Delete associated records
        if user.role == 'Student':
            student = Student.query.filter_by(user_id=user.id).first()
            if student:
                # Delete course registrations and scores
                CourseRegistration.query.filter_by(student_id=student.id).delete()
                Score.query.filter_by(student_id=student.id).delete()
                db.session.delete(student)

        # Delete user
        db.session.delete(user)
        db.session.commit()

        flash('User deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting user: {str(e)}")
        flash('Error deleting user. Please try again.', 'error')

    return redirect(url_for('views.admin_dashboard'))

@views_bp.route('/')
def index():
    # Simple roles list without using url_for to avoid any context issues
    roles = [
        {'name': 'Admin', 'description': 'Manage users and courses', 'url': '/auth/login'},
        {'name': 'Student', 'description': 'Register courses and view results', 'url': '/auth/login'},
        {'name': 'Lecturer', 'description': 'Upload scores for courses', 'url': '/auth/login'},
        {'name': 'Finance', 'description': 'Manage student payments', 'url': '/auth/login'}
    ]
    return render_template('index.html', roles=roles)


@views_bp.route('/admin/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_course(course_id):
    if not validate_admin_access():
        return redirect(get_redirect_url())

    course = db.session.get(Course, course_id)
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('views.admin_dashboard'))

    lecturers = User.query.filter_by(role='Lecturer', is_active=True).order_by(User.name).all()

    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()
        title = request.form.get('title', '').strip()
        unit = request.form.get('unit', '').strip()
        session = request.form.get('session', '').strip()
        semester = request.form.get('semester', '').strip()
        lecturer_id = request.form.get('lecturer_id', '').strip()

        # Validation
        errors = []
        if not all([code, title, unit, session, semester]):
            errors.append('All fields except lecturer are required')
        if not unit.isdigit() or not (1 <= int(unit) <= 6):
            errors.append('Course units must be between 1 and 6')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('admin_edit_course.html',
                                 course=course,
                                 lecturers=lecturers)

        # Check if course code is already taken by another course
        if code != course.code and Course.query.filter_by(code=code).first():
            flash('Course code already exists', 'error')
            return render_template('admin_edit_course.html',
                                 course=course,
                                 lecturers=lecturers)

        try:
            course.code = code
            course.title = title
            course.unit = int(unit)
            course.session = session
            course.semester = semester
            course.lecturer_id = int(lecturer_id) if lecturer_id else None

            db.session.commit()
            flash('Course updated successfully', 'success')
            return redirect(url_for('views.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating course: {str(e)}")
            flash('Error updating course. Please try again.', 'error')
            return render_template('admin_edit_course.html',
                                 course=course,
                                 lecturers=lecturers)

    return render_template('admin_edit_course.html', course=course, lecturers=lecturers)


@views_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not validate_admin_access():
        return redirect(get_redirect_url())

    users = User.query.order_by(User.role, User.name).all()
    courses = Course.query.order_by(Course.code).all()

    user_count = len(users)
    student_count = len([u for u in users if u.role == 'Student'])
    lecturer_count = len([u for u in users if u.role == 'Lecturer'])
    course_count = len(courses)

    return render_template('admin_dashboard.html', users=users, courses=courses,
                         user_count=user_count, student_count=student_count,
                         lecturer_count=lecturer_count, course_count=course_count)

@views_bp.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    if not validate_admin_access():
        return redirect(get_redirect_url())

    if request.method == 'POST':
        unique_id = request.form.get('unique_id', '').strip()
        name = request.form.get('name', '').strip()
        role = request.form.get('role', '').strip()
        faculty = request.form.get('faculty', '').strip()
        department = request.form.get('department', '').strip()

        # Validation
        errors = []
        if not all([unique_id, name, role, faculty, department]):
            errors.append('All fields are required')
        if len(unique_id) < 3:
            errors.append('Unique ID must be at least 3 characters long')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('admin_add_user.html',
                                 unique_id=unique_id,
                                 name=name,
                                 role=role,
                                 faculty=faculty,
                                 department=department)

        if User.query.filter_by(unique_id=unique_id).first():
            flash('Unique ID already exists', 'error')
            return render_template('admin_add_user.html',
                                 unique_id=unique_id,
                                 name=name,
                                 role=role,
                                 faculty=faculty,
                                 department=department)

        try:
            user = User(
                unique_id=unique_id,
                name=name,
                role=role,
                faculty=faculty,
                department=department,
                is_active=False,
                must_change_password=True
            )
            db.session.add(user)
            db.session.commit()

            if role == 'Student':
                student = Student(user_id=user.id, balance=0.0)
                db.session.add(student)
                db.session.commit()

            #I cut db session commit from here
            flash(f'User {name} ({unique_id}) added successfully', 'success')
            return redirect(url_for('views.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Error adding user. Please try again.', 'error')
            return render_template('admin_add_user.html',
                                 unique_id=unique_id,
                                 name=name,
                                 role=role,
                                 faculty=faculty,
                                 department=department)

    # GET request - show empty form
    return render_template('admin_add_user.html')


@views_bp.route('/admin/add_course', methods=['GET', 'POST'])
@login_required
def admin_add_course():
    if not validate_admin_access():
        return redirect(get_redirect_url())

    lecturers = User.query.filter_by(role='Lecturer', is_active=True).order_by(User.name).all()

    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()
        title = request.form.get('title', '').strip()
        unit = request.form.get('unit', '').strip()
        session = request.form.get('session', '').strip()
        semester = request.form.get('semester', '').strip()
        lecturer_id = request.form.get('lecturer_id', '').strip()

        errors = []
        if not all([code, title, unit, session, semester]):
            errors.append('All fields except lecturer are required')
        if not unit.isdigit() or not (1 <= int(unit) <= 6):
            errors.append('Course units must be between 1 and 6')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('admin_add_course.html', lecturers=lecturers,
                                 code=code, title=title, unit=unit, session=session,
                                 semester=semester, lecturer_id=lecturer_id)

        if Course.query.filter_by(code=code).first():
            flash('Course code already exists', 'error')
            return render_template('admin_add_course.html', lecturers=lecturers,
                                 code=code, title=title, unit=unit, session=session,
                                 semester=semester, lecturer_id=lecturer_id)

        try:
            course = Course(
                code=code,
                title=title,
                unit=int(unit),
                session=session,
                semester=semester,
                lecturer_id=int(lecturer_id) if lecturer_id else None
            )
            db.session.add(course)
            db.session.commit()

            # Log successful action before redirecting
            logger.info(f"User {current_user.unique_id} successfully added course {code}.")


            flash(f'Course {code} - {title} added successfully', 'success')
            return redirect(url_for('views.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Error adding course. Please try again.', 'error')
            return render_template('admin_add_course.html', lecturers=lecturers,
                                 code=code, title=title, unit=unit, session=session,
                                 semester=semester, lecturer_id=lecturer_id)

    return render_template('admin_add_course.html', lecturers=lecturers, now=datetime.now)

# --- Student Routes ---
@views_bp.route('/student/dashboard')
@login_required
def student_dashboard():
    if not validate_student_access():
        return redirect(get_redirect_url())

    student = Student.query.filter_by(user_id=current_user.id).first()
    if not student:
        flash('Student profile not found. Please contact administration.', 'error')
        return redirect(url_for('auth.logout'))

    # Get registered courses
    registrations = CourseRegistration.query.filter_by(student_id=student.id).all()
    registered_courses = [reg.course for reg in registrations if reg.course]

    return render_template('student_dashboard.html',
                         student=student,
                         registered_courses=registered_courses)


@views_bp.route('/student/register_course', methods=['GET', 'POST'])
@login_required
def student_register_course():
    if not validate_student_access():
        return redirect(get_redirect_url())

    student = Student.query.filter_by(user_id=current_user.id).first()
    if not student:
        flash('Student profile not found. Please contact administration.', 'error')
        return redirect(url_for('auth.logout'))

    # Get ALL available courses (not filtering out registered ones for debugging)
    all_courses = Course.query.all()

    # Get registered course IDs
    registered_course_ids = [reg.course_id for reg in CourseRegistration.query.filter_by(student_id=student.id).all()]

    # Available courses are those NOT already registered
    available_courses = [course for course in all_courses if course.id not in registered_course_ids]

    # Debug information
    print(f"Total courses: {len(all_courses)}")
    print(f"Registered courses: {registered_course_ids}")
    print(f"Available courses: {len(available_courses)}")

    if request.method == 'POST':
        selected_courses = request.form.getlist('courses')

        if not selected_courses:
            flash('Please select at least one course to register', 'error')
            return render_template('student_register_course.html',
                                 courses=available_courses,
                                 all_courses=all_courses,
                                 registered_courses=registered_course_ids)

        try:
            for course_id in selected_courses:
                course = db.session.get(Course, int(course_id))
                if course and not CourseRegistration.query.filter_by(student_id=student.id, course_id=course.id).first():
                    registration = CourseRegistration(
                        student_id=student.id,
                        course_id=course.id,
                        date_registered=datetime.now()
                    )
                    db.session.add(registration)

            db.session.commit()
            flash('Courses registered successfully', 'success')
            return redirect(url_for('views.student_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Error registering courses. Please try again.', 'error')
            return render_template('student_register_course.html',
                                 courses=available_courses,
                                 all_courses=all_courses,
                                 registered_courses=registered_course_ids)

    return render_template('student_register_course.html',
                         courses=available_courses,
                         all_courses=all_courses,
                         registered_courses=registered_course_ids)


@views_bp.route('/student/results')
@login_required
def student_results():
    if not validate_student_access():
        return redirect(get_redirect_url())

    student = Student.query.filter_by(user_id=current_user.id).first()
    if not student:
        flash('Student profile not found. Please contact administration.', 'error')
        return redirect(url_for('auth.logout'))

    try:
        # Get all scores for the current student
        all_scores = Score.query.filter_by(student_id=student.id).all()

        # Organize results by session and semester
        results_by_session_semester = {}
        for score in all_scores:
            if score.course:
                session = score.course.session
                semester = score.course.semester

                if session not in results_by_session_semester:
                    results_by_session_semester[session] = {}
                if semester not in results_by_session_semester[session]:
                    results_by_session_semester[session][semester] = []

                results_by_session_semester[session][semester].append(score)

        # Calculate GPA for each semester and overall CGPA
        gpa_by_session_semester = {}
        overall_total_points = 0
        overall_total_units = 0

        for session, semesters in results_by_session_semester.items():
            gpa_by_session_semester[session] = {}
            for semester, scores in semesters.items():
                total_points = sum(score.calculate_grade_point() for score in scores)
                total_units = sum(score.course.unit for score in scores if score.course)
                gpa = round(total_points / total_units, 2) if total_units > 0 else 0.0
                gpa_by_session_semester[session][semester] = gpa

                overall_total_points += total_points
                overall_total_units += total_units

        # Calculate CGPA
        cgpa = round(overall_total_points / overall_total_units, 2) if overall_total_units > 0 else 0.0

        # Determine final grade based on CGPA
        if cgpa >= 3.0:
            final_grade = "DISTINCTION"
        # elif cgpa >= 2.5:
        #     final_grade = "CREDIT"
        # elif cgpa >= 2.0:
        #     final_grade = "PASS"
        else:
            final_grade = "PASS"

        return render_template(
            'student_results.html',
            results_by_session_semester=results_by_session_semester,
            gpa_by_session_semester=gpa_by_session_semester,
            cgpa=cgpa,
            final_grade=final_grade,
            student=student
        )

    except Exception as e:
        logging.error(f"Error loading student results: {str(e)}")
        flash('Error loading results. Please try again.', 'error')
        return redirect(url_for('views.student_dashboard'))


@views_bp.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not validate_admin_access():
        return redirect(get_redirect_url())

    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('views.admin_dashboard'))

    if request.method == 'POST':
        unique_id = request.form.get('unique_id', '').strip()
        name = request.form.get('name', '').strip()
        role = request.form.get('role', '').strip()
        faculty = request.form.get('faculty', '').strip()
        department = request.form.get('department', '').strip()
        is_active = request.form.get('is_active') == 'on'

        # Validation
        errors = []
        if not all([unique_id, name, role, faculty, department]):
            errors.append('All fields are required')
        if len(unique_id) < 3:
            errors.append('Unique ID must be at least 3 characters long')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('admin_edit_user.html', user=user)

        # Check if unique_id is already taken by another user
        if unique_id != user.unique_id and User.query.filter_by(unique_id=unique_id).first():
            flash('Unique ID already exists', 'error')
            return render_template('admin_edit_user.html', user=user)

        try:
            user.unique_id = unique_id
            user.name = name
            user.role = role
            user.faculty = faculty
            user.department = department
            user.is_active = is_active

            # Handle student record if role changed
            if role == 'Student':
                student = Student.query.filter_by(user_id=user.id).first()
                if not student:
                    student = Student(user_id=user.id, balance=0.0)
                    db.session.add(student)
            else:
                # Remove student record if role changed from Student
                student = Student.query.filter_by(user_id=user.id).first()
                if student:
                    db.session.delete(student)

            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('views.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating user: {str(e)}")
            flash('Error updating user. Please try again.', 'error')
            return render_template('admin_edit_user.html', user=user)

    return render_template('admin_edit_user.html', user=user)

# Add this route to your views.py if it's missing
@views_bp.route('/lecturer/upload_score/<int:course_id>', methods=['GET', 'POST'])
@login_required
def lecturer_upload_score(course_id):
    if not validate_lecturer_access():
        return redirect(get_redirect_url())

    course = db.session.get(Course, course_id)
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('views.lecturer_dashboard'))

    if course.lecturer_id != current_user.id:
        flash('You are not authorized to upload scores for this course', 'error')
        return redirect(url_for('views.lecturer_dashboard'))

    # Get all students registered for this course
    registrations = CourseRegistration.query.filter_by(course_id=course_id).all()
    students_in_course = [r.student for r in registrations if r.student]

    # Get existing scores
    existing_scores = {score.student_id: score for score in Score.query.filter_by(course_id=course_id).all()}

    if request.method == 'POST':
        try:
            for student in students_in_course:
                ca_score_str = request.form.get(f'ca_score_{student.id}', '').strip()
                exam_score_str = request.form.get(f'exam_score_{student.id}', '').strip()

                # Handle empty scores
                ca_score = float(ca_score_str) if ca_score_str else None
                exam_score = float(exam_score_str) if exam_score_str else None

                # Validate score ranges if provided
                if ca_score is not None and not (0 <= ca_score <= 40):
                    flash(f'Invalid CA score for student {student.user.name}. Must be between 0-40.', 'error')
                    return redirect(url_for('views.lecturer_upload_score', course_id=course_id))

                if exam_score is not None and not (0 <= exam_score <= 60):
                    flash(f'Invalid Exam score for student {student.user.name}. Must be between 0-60.', 'error')
                    return redirect(url_for('views.lecturer_upload_score', course_id=course_id))

                # Only update if at least one score is provided
                if ca_score is not None or exam_score is not None:
                    score = existing_scores.get(student.id)
                    if not score:
                        score = Score(student_id=student.id, course_id=course_id)
                        db.session.add(score)

                    if ca_score is not None:
                        score.ca_score = ca_score
                    if exam_score is not None:
                        score.exam_score = exam_score

            db.session.commit()
            flash('Scores uploaded successfully', 'success')
            return redirect(url_for('views.lecturer_dashboard'))

        except ValueError:
            flash('Invalid score format. Please enter numbers for scores.', 'error')
            return redirect(url_for('views.lecturer_upload_score', course_id=course_id))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error uploading scores: {str(e)}")
            flash('Error uploading scores. Please try again.', 'error')
            return redirect(url_for('views.lecturer_upload_score', course_id=course_id))

    return render_template('lecturer_upload_score.html',
                         course=course,
                         students=students_in_course,
                         existing_scores=existing_scores)

# --- Lecturer Routes ---
@views_bp.route('/lecturer/dashboard')
@login_required
def lecturer_dashboard():
    if not validate_lecturer_access():
        return redirect(get_redirect_url())

    courses = Course.query.filter_by(lecturer_id=current_user.id).order_by(Course.code).all()

    course_count = len(courses)
    student_count = 0
    for course in courses:
        registrations = CourseRegistration.query.filter_by(course_id=course.id).count()
        student_count += registrations

    return render_template('lecturer_dashboard.html', courses=courses,

                         course_count=course_count, student_count=student_count)
