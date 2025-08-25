from flask_login import UserMixin
from sqlalchemy.orm import validates
from . import db
import re

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    unique_id = db.Column(db.String(50), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    faculty = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    student = db.relationship('Student', back_populates='user', uselist=False, cascade="all, delete-orphan")
    courses = db.relationship('Course', back_populates='lecturer')
    
    @validates('email')
    def validate_email(self, key, email):
        if email is not None and email.strip() != '':
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                raise ValueError('Invalid email format')
        return email
    
    @validates('role')
    def validate_role(self, key, role):
        valid_roles = ['Admin', 'Student', 'Lecturer', 'Finance']
        if role not in valid_roles:
            raise ValueError('Invalid role specified')
        return role

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    balance = db.Column(db.Float, default=0.0)
    user = db.relationship('User', back_populates='student')
    registrations = db.relationship('CourseRegistration', back_populates='student', cascade="all, delete-orphan")
    scores = db.relationship('Score', back_populates='student', cascade="all, delete-orphan")

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    unit = db.Column(db.Integer, nullable=False)
    session = db.Column(db.String(10), nullable=False)
    semester = db.Column(db.String(10), nullable=False)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    lecturer = db.relationship('User', back_populates='courses')
    registrations = db.relationship('CourseRegistration', back_populates='course', cascade="all, delete-orphan")
    scores = db.relationship('Score', back_populates='course', cascade="all, delete-orphan")

class CourseRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    date_registered = db.Column(db.DateTime, nullable=False)
    student = db.relationship('Student', back_populates='registrations')
    course = db.relationship('Course', back_populates='registrations')
    
    __table_args__ = (
        db.UniqueConstraint('student_id', 'course_id', name='unique_student_course_registration'),
    )

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    ca_score = db.Column(db.Float, nullable=True)
    exam_score = db.Column(db.Float, nullable=True)
    student = db.relationship('Student', back_populates='scores')
    course = db.relationship('Course', back_populates='scores')
    
    __table_args__ = (
        db.UniqueConstraint('student_id', 'course_id', name='unique_student_course_score'),
    )
    
    def calculate_grade_point(self):
        if not self.course:
            return 0.0
            
        total_score = (self.ca_score or 0) + (self.exam_score or 0)
        if total_score >= 70:
            return 5.0 * self.course.unit
        elif total_score >= 60:
            return 4.0 * self.course.unit
        elif total_score >= 50:
            return 3.0 * self.course.unit
        elif total_score >= 45:
            return 2.0 * self.course.unit
        elif total_score >= 40:
            return 1.0 * self.course.unit
        return 0.0
