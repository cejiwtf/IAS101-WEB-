# Secure Web Application - Documentation
**Framework**: Flask (Python)  
**Version**: Flask 2.3.3  
**Group Members**: [Add your names here]

---

## 📋 Project Overview

This is a secure web application built using **Flask framework** that implements industry-standard security practices including authentication, authorization, input validation, and password security features.

---

## 🎯 Core Features Implemented

### 1. ✅ Login + Registration System
- **Location**: `app.py` lines 93-146
- Users can register with email and password
- Secure login with session management
- Logout functionality
- Session handling via Flask-Login

### 2. ✅ Password Hashing (Bcrypt)
- **Location**: `app.py` line 107 (registration), line 138 (login verification)
- **Implementation**:
  ```python
  # During registration (line 107)
  hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
  
  # During login verification (line 138)
  bcrypt.check_password_hash(user.password, form.password.data)
  ```
- Uses **bcrypt** algorithm with automatic salt generation
- Passwords are NEVER stored in plain text

### 3. ✅ Role-Based Access Control (RBAC)
- **Roles**: Admin, User
- **Location**: 
  - Role assignment: `app.py` line 110
  - Role checking: `app.py` lines 156-159
- **Implementation**:
  ```python
  # First registered user becomes admin
  role = "admin" if User.query.count() == 0 else "user"
  
  # Admin route protection (lines 154-162)
  @app.route("/admin")
  @login_required
  def admin():
      if current_user.role != "admin":
          flash("Access denied. Admin privileges required.", "danger")
          return redirect(url_for('dashboard'))
  ```

### 4. ✅ Protected Routes
- **Location**: `app.py` - All protected routes use `@login_required` decorator
- **Examples**:
  - `/dashboard` (line 148-151) - requires login
  - `/admin` (line 153-162) - requires login + admin role
  - `/logout` (line 164-169) - requires login
- **How it works**:
  - Unauthenticated users are automatically redirected to login page
  - Cannot access protected pages by typing URL directly
  - Flask-Login manages session state

### 5. ✅ Input Validation & Security

#### **SQL Injection Prevention**
- **Method**: Using SQLAlchemy ORM (Object-Relational Mapping)
- **Location**: All database queries in `app.py`
- **How it works**: SQLAlchemy automatically parameterizes queries, preventing SQL injection
- **Example**:
  ```python
  # Safe - parameterized query (line 101)
  User.query.filter_by(email=form.email.data).first()
  
  # This is SAFE because SQLAlchemy handles escaping
  # Not vulnerable to: ' OR 1=1--
  ```

#### **XSS Prevention**
- **Method**: Jinja2 template auto-escaping + WTForms validation
- **Location**: All templates use `{{ }}` which auto-escapes HTML
- **How it works**: 
  - Jinja2 automatically escapes user input in templates
  - Prevents execution of malicious scripts
- **Example**:
  ```html
  <!-- In templates - automatically escaped -->
  {{ form.email.data }}  <!-- If input is <script>alert('xss')</script>, it renders as text -->
  ```

#### **CSRF Protection**
- **Method**: Flask-WTF provides CSRF tokens
- **Location**: All forms have `{{ form.hidden_tag() }}`
- **Implementation**: Every form submission requires a valid CSRF token

#### **Form Validation**
- **Location**: `app.py` lines 61-81 (RegisterForm & LoginForm)
- **Validators Used**:
  - `DataRequired()` - ensures fields are not empty
  - `Email()` - validates email format
  - `Length(min=8)` - enforces minimum password length
  - Custom validator for password strength (lines 38-59)

---

## 🔐 Additional Security Feature: Password Strength Meter

**Feature Chosen**: Password Strength Meter (as per project requirements)

### Implementation Details:
- **Location**: `register.html` lines 58-142 (JavaScript)
- **How it works**:
  1. Real-time password analysis as user types
  2. Checks 5 criteria:
     - Length ≥ 8 characters
     - Contains uppercase letter (A-Z)
     - Contains lowercase letter (a-z)
     - Contains number (0-9)
     - Contains special character (!@#$%^&* etc.)
  3. Visual feedback with color coding:
     - Red (Weak) - 0-1 criteria met
     - Orange (Fair/Good) - 2-3 criteria met
     - Green (Strong/Very Strong) - 4-5 criteria met
  4. Shows missing requirements in real-time

### Server-Side Validation:
- **Location**: `app.py` lines 38-59
- Password requirements are enforced BOTH client-side (JavaScript) AND server-side (Python)
- Server-side validation prevents bypassing client-side checks

---

## 🔒 Additional Security Measures

### Security Headers
- **Location**: `app.py` lines 15-21
```python
response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevents MIME sniffing
response.headers['X-Frame-Options'] = 'DENY'            # Prevents clickjacking
response.headers['X-XSS-Protection'] = '1; mode=block'  # XSS protection
```

### Error Handling
- Custom 404 and 403 error pages (lines 171-177)
- Prevents information leakage through error messages

---

## 🚀 Setup Instructions

### Prerequisites:
- Python 3.7 or higher
- pip (Python package manager)

### Installation Steps:

1. **Clone/Download the project**
   ```bash
   cd path/to/IAS-main
   ```

2. **Install required packages**
   ```bash
   pip install -r requirements.txt
   ```
   
   Or if that doesn't work:
   ```bash
   python -m pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open your browser
   - Go to: `http://127.0.0.1:5000` or `http://localhost:5000`

5. **Database is created automatically**
   - SQLite database file: `instance/site.db`
   - Created automatically on first run

---

## 👥 Test Accounts

### Default Admin Account (Created Automatically):
- **Email**: `admin@example.com`
- **Password**: `Admin@123`
- **Role**: Admin
- **Access**: Can access `/admin` page to view all users

### Create Additional Users:
1. Go to `/register`
2. Enter email and password (must meet requirements)
3. New users get "user" role by default
4. Can access `/dashboard` but NOT `/admin`

---

## 📂 Project Structure

```
IAS-main/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── templates/             # HTML templates (Jinja2)
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── register.html     # Registration with password meter
│   ├── dashboard.html    # User dashboard (protected)
│   ├── admin.html        # Admin panel (admin only)
│   ├── 403.html          # Access denied page
│   └── 404.html          # Page not found
├── static/               # Static files (CSS, JS, images)
│   └── strength.js       # Password strength meter script
└── instance/             # Instance folder (created automatically)
    └── site.db           # SQLite database
```

---

## 🛡️ Security Demonstration Points

### For Demo/Defense - Be Ready to Explain:

1. **Where password hashing happens:**
   - Show `app.py` line 107 during registration
   - Show `app.py` line 138 during login verification
   - Explain bcrypt algorithm and automatic salting

2. **How roles are checked:**
   - Show role assignment at line 110
   - Show admin route protection at lines 156-159
   - Demo: Try accessing `/admin` as regular user

3. **How routes are protected:**
   - Show `@login_required` decorator usage
   - Demo: Try accessing `/dashboard` without logging in
   - Show redirect to login page

4. **How input is validated:**
   - Show WTForms validators in RegisterForm (lines 61-71)
   - Show custom password strength validator (lines 38-59)
   - Demo: Try registering with weak password
   - Demo: Try SQL injection in login form (show it fails)

5. **SQL Injection Prevention:**
   - Explain SQLAlchemy ORM usage
   - Show parameterized queries
   - Demo attempt: Enter `' OR 1=1--` in email field (will fail safely)

6. **XSS Prevention:**
   - Show Jinja2 auto-escaping in templates
   - Demo attempt: Register with `<script>alert('XSS')</script>` as email
   - Show it renders as text, not executed

---

## 📊 Technologies Used

| Technology | Purpose | Version |
|------------|---------|---------|
| Flask | Web framework | 2.3.3 |
| Flask-SQLAlchemy | Database ORM | 3.0.5 |
| Flask-Login | Session management | 0.6.3 |
| Flask-Bcrypt | Password hashing | 1.0.1 |
| Flask-WTF | Form handling & CSRF | 1.1.1 |
| WTForms | Form validation | 3.0.1 |
| SQLite | Database | Built-in |
| Jinja2 | Template engine | Built-in with Flask |

---

## 🎓 Learning Points / Key Takeaways

1. **Never store passwords in plain text** - Always use bcrypt or similar
2. **Always validate on server-side** - Client-side validation can be bypassed
3. **Use ORM to prevent SQL injection** - Don't construct raw SQL queries
4. **Implement proper access control** - Check user roles before allowing access
5. **Use CSRF protection** - Prevent cross-site request forgery attacks
6. **Provide user feedback** - Password strength meter improves security

---

## 🐛 Known Limitations / Future Improvements

1. **Database**: Currently using SQLite (file-based). For production, use PostgreSQL/MySQL
2. **Secret Key**: Hardcoded in `app.py` line 11. Should use environment variables
3. **Email Verification**: Not implemented (could add email confirmation)
4. **Password Reset**: Not implemented (could add forgot password feature)
5. **Rate Limiting**: Not implemented (could add login attempt limiting)
6. **Two-Factor Authentication**: Not implemented (could add as enhancement)

---

## 📞 Support / Questions

For questions during demo or evaluation, any group member can explain:
- The code structure and flow
- Security implementations
- Design decisions
- How to test each feature

---

## ✅ Checklist - Project Requirements

- [x] Framework used: Flask (Python)
- [x] Login + Registration
- [x] Password hashing (bcrypt)
- [x] Role-Based Access (Admin/User)
- [x] Protected routes
- [x] Input validation (SQL Injection & XSS prevention)
- [x] Additional feature: Password Strength Meter
- [x] Documentation
- [x] Test accounts provided
- [x] Ready for demo

---

**Last Updated**: February 2026  
**Project Status**: Complete and ready for demonstration
