import matplotlib
matplotlib.use('Agg')  # Set the backend to non-interactive Agg
from flask import render_template, redirect, url_for, flash, request, session, Blueprint, jsonify, get_flashed_messages
from . import db, bcrypt, mail
from .models import User, Admin, Project, Sprint, UserStory
from flask_mail import Message
from app import mail
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import random
import re
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.dates import date2num

def generate_burndown_chart(project_id):
    project = Project.query.filter_by(project_id=project_id).first()
    sprints = Sprint.query.filter_by(project_id=project_id).order_by(Sprint.sprint_number).all()
    
    # Get total story points for the project
    total_points = sum([story.story_point for story in UserStory.query.filter_by(project_id=project_id).all()])
    
    # Create data points for actual and ideal burndown
    sprint_labels = []
    remaining_points = []
    ideal_points = []
    
    remaining = total_points
    points_per_sprint = total_points / len(sprints) if sprints else 0
    
    for sprint in sprints:
        sprint_labels.append(f'Sprint {sprint.sprint_number}')
        completed_points = sum([story.story_point for story in UserStory.query.filter_by(
            project_id=project_id, 
            sprint_id=sprint.id, 
            status='completed'
        ).all()])
        remaining -= completed_points
        remaining_points.append(remaining)
        ideal_points.append(max(0, total_points - (points_per_sprint * sprint.sprint_number)))

    plt.figure(figsize=(10, 6))
    plt.plot(sprint_labels, remaining_points, 'b-', marker='o', label='Actual')
    plt.plot(sprint_labels, ideal_points, 'r--', marker='x', label='Ideal')
    plt.title('Burndown Chart')
    plt.xlabel('Sprints')
    plt.ylabel('Remaining Story Points')
    plt.legend()
    plt.grid(True)
    
    # Save to base64
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close()
    
    return base64.b64encode(image_png).decode('utf-8')

def generate_burnup_chart(project_id):
    project = Project.query.filter_by(project_id=project_id).first()
    sprints = Sprint.query.filter_by(project_id=project_id).order_by(Sprint.sprint_number).all()
    
    # Get total story points
    total_points = sum([story.story_point for story in UserStory.query.filter_by(project_id=project_id).all()])
    
    # Create data points
    sprint_labels = []
    completed_points = []
    total_line = []
    
    completed = 0
    for sprint in sprints:
        sprint_labels.append(f'Sprint {sprint.sprint_number}')
        sprint_completed = sum([story.story_point for story in UserStory.query.filter_by(
            project_id=project_id, 
            sprint_id=sprint.id, 
            status='completed'
        ).all()])
        completed += sprint_completed
        completed_points.append(completed)
        total_line.append(total_points)

    plt.figure(figsize=(10, 6))
    plt.plot(sprint_labels, completed_points, 'g-', marker='o', label='Completed')
    plt.plot(sprint_labels, total_line, 'b--', label='Total Scope')
    plt.title('Burnup Chart')
    plt.xlabel('Sprints')
    plt.ylabel('Story Points')
    plt.legend()
    plt.grid(True)
    
    # Save to base64
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close()
    
    return base64.b64encode(image_png).decode('utf-8')

def generate_velocity_chart(sprint_details):
    sprint_numbers = [f'Sprint {sprint["sprint_no"]}' for sprint in sprint_details]
    velocities = [sprint['velocity'] for sprint in sprint_details]
    
    plt.figure(figsize=(10, 6))
    plt.bar(sprint_numbers, velocities, color='blue')
    plt.title('Sprint Velocity Chart')
    plt.xlabel('Sprints')
    plt.ylabel('Velocity (Story Points)')
    plt.grid(True, axis='y')
    
    # Calculate and plot average velocity
    avg_velocity = sum(velocities) / len(velocities) if velocities else 0
    plt.axhline(y=avg_velocity, color='r', linestyle='--', label=f'Avg: {avg_velocity:.1f}')
    plt.legend()
    
    # Save to base64
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close()
    
    return base64.b64encode(image_png).decode('utf-8')

auth = Blueprint("auth", __name__, template_folder='templates/auth', static_folder='static')
admin = Blueprint("admin", __name__, template_folder='templates/admin', static_folder='static', url_prefix='/admin')
main = Blueprint('main', __name__)

INACTIVITY_TIMEOUT = timedelta(minutes=15)
otp_storage = {}
@auth.route('/extend_session', methods=['POST'])
def extend_session():
    if 'last_activity' in session:
        # Extend the session by 10 minutes
        session['last_activity'] = (datetime.now() + timedelta(minutes=10)).isoformat()
        return jsonify({'success': True})
    return jsonify({'success': False}), 400
@auth.route('/check_inactivity')
def check_inactivity_status():
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        time_since_last_activity = datetime.now() - last_activity
        if time_since_last_activity > INACTIVITY_TIMEOUT:
            return jsonify({'inactive': True, 'time_left': 0})
        else:
            time_left = INACTIVITY_TIMEOUT - time_since_last_activity
            return jsonify({'inactive': False, 'time_left': time_left.total_seconds()})
    return jsonify({'inactive': False, 'time_left': None})

def generate_mfa_qr_code(user_email,mfa_secret):
    # Create a TOTP object
    totp = pyotp.TOTP(mfa_secret)

    # Generate the provisioning URI for the QR code
    provisioning_uri = totp.provisioning_uri(name=user_email, issuer_name="AgileApp")

    # Generate the QR code
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return qr_code
def create_initial_admin():
    admin_email = 'infosysdhruv@gmail.com'
    admin_password = bcrypt.generate_password_hash('123', 10)

    # Check if an admin with the given email already exists
    admin_exists = Admin.query.filter_by(email=admin_email).first()

    if not admin_exists:
        admin = Admin(email=admin_email, password=admin_password)
        db.session.add(admin)
        db.session.commit()
        print("Initial admin created successfully.")
    else:
        print("Initial admin already exists.")
# Admin login
@admin.route('/', methods=["POST", "GET"])
def adminIndex():
    create_initial_admin()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect(url_for('admin.adminIndex'))

        # Check if the admin exists and the password is correct
        admin = Admin.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['admin_email'] = admin.email
            session['admin_password']=admin.password
            flash('Login Successful', 'success')
            return redirect(url_for('admin.adminDashboard'))
        else:
            flash('Invalid Email or Password', 'danger')
            return redirect(url_for('admin.adminIndex'))
    else:
        return render_template('index.html', title="Admin Login")
@admin.route('/get-user-stats', methods=['GET'])
def get_user_stats():
    users = User.query.all()
    user_data = []

    active_count = 0
    logged_out_count = 0
    rejected_count = 0
    approved_count = 0
    pending_count = 0

    for user in users:
        if user.status == 3:  # Active users
            active_count += 1
        elif user.status == 4:  # Logged out users
            logged_out_count += 1
        elif user.status == 2:  # Rejected users
            rejected_count += 1
        elif user.status == 1:  # Approved users
            approved_count += 1
        else:  # Pending users
            pending_count += 1

        # Handle last_login for rejected and pending users
        if user.status == 2 or user.status == 0:  # Rejected or Pending
            last_login = "N/A"
        else:
            last_login = user.logout if user.logout else "N/A"  # Handle null values for other statuses

        user_data.append({
            "id": user.id,
            "name": user.name,
            "status": user.status,
            "last_login": last_login
        })

    return jsonify({
        "users": user_data,
        "active_count": active_count,
        "logged_out_count": logged_out_count,
        "rejected_count": rejected_count,
        "approved_count": approved_count,
        "pending_count": pending_count
    })
# Admin Dashboard
@admin.route('/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect(url_for('auth.home'))

    totalUser = User.query.count()
    totalApprove = User.query.filter_by(status=1).count()
    NotTotalApprove = User.query.filter_by(status=0).count()

    return render_template('admin/dashboard.html', title="Admin Dashboard", totalUser=totalUser, totalApprove=totalApprove, NotTotalApprove=NotTotalApprove)
# Admin get all users
@admin.route('/get-all-user', methods=["POST", "GET"])
def adminGetAllUser():
    # Clear any existing flash messages
    get_flashed_messages()
    if not session.get('admin_id'):
        return redirect(url_for('auth.home'))
    if request.method == "POST":
        search = request.form.get('search')
        users = User.query.filter(User.name.like('%' + search + '%')).all()
        return render_template('all-user.html', title='Approve User', users=users)
    else:
        users = User.query.all()
        return render_template('all-user.html', title='Approve User', users=users)

@admin.route("/reject_user/<int:id>")
def reject_user(id):
    if not session.get('admin_id'):
        return redirect(url_for('auth.home'))
    user = User.query.get(id)
    if user:
        user.status=2
        user_email = user.email
        db.session.commit()

        msg = Message(
            subject="Account Rejection Notification",
            recipients=[user_email],
        )
        msg.body = f"Dear User,\n\nWe regret to inform you that your registration request has been rejected.\n\nBest Regards,\nAdmin Team"
        mail.send(msg)

        flash("User has been rejected and notified via email.", "success")
    else:
        flash("User not found.", "warning")
    return redirect(url_for("admin.adminGetAllUser"))
# Admin approve user
@admin.route('/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect(url_for('auth.home'))
    User.query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    user = User.query.get(id)
    user_email = user.email
    username = user.name
    msg = Message(
            subject="Account Approval Notification",

            recipients=[user_email]
        )
    msg.body = f"Dear User,\n\nWe kindly  inform you that your registration request has been Approved. Please you can login now \n\nBest Regards,\nAdmin Team"
    mail.send(msg)
    flash(f'{user.name}  has been approved and notified via email..', 'success')
    return redirect(url_for('admin.adminGetAllUser'))

# Admin change password
@admin.route('/change-admin-password', methods=["POST", "GET"])
def adminChangePassword():
    admin = Admin.query.get(1)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect(url_for('admin.adminChangePassword'))
        else:
            Admin.query.filter_by(email=email).update(dict(password=bcrypt.generate_password_hash(password, 10)))
            db.session.commit()
            flash('Admin Password Updated Successfully', 'success')
            return redirect(url_for('admin.adminChangePassword'))
    else:
        return render_template('admin-change-password.html', title='Admin Change Password', admin=admin)

# Admin logout
@admin.route('/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect(url_for('auth.login'))
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    return redirect(url_for('auth.home'))

@auth.route('/')
def home():
    return render_template('homepage.html',title="Agile Management")

# Auth register login.html contain this route
@auth.route('/register')
def register():
    # Clear any existing flash messages
    get_flashed_messages()
    return render_template('register.html', title="Sign-up")

# Auth login
@auth.route('/login')
def login():
    # Clear any existing flash messages
    get_flashed_messages()
    return render_template('login.html', title='Login')

# Auth signup
@auth.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        dob_str= request.form.get('dob')
        gender=request.form.get('gender')
        address=request.form.get('address')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        role=request.form.get('role')
        mfa=request.form.get('enable_2fa')=='true'
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('auth.signup'))

        existing_user = User.query.filter((User.email == email) | (User.phone == phone)).first()
        if existing_user:
            flash('Email or phone number already registered.', 'danger')
            return redirect(url_for('auth.signup'))

        indian_phone_regex = r'^(\+91[\-\s]?)?[6789]\d{9}$'

        if not re.match(indian_phone_regex, phone):
            flash('Please enter a valid Indian phone number.', 'danger')
            return redirect(url_for('auth.signup'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if mfa:
            mfa_secret = pyotp.random_base32()
        else:
            mfa_secret=None
        new_user = User(name=name, email=email, phone=phone, password=hashed_password,role=role,mfa_secret=mfa_secret,dob=dob,gender=gender,address=address,mfa=int(mfa))
        # Save the user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Wait for admin approval.', 'success')
            msg = Message(
            subject="New User Registration Alert",
            recipients=['teamofadm1n123@gmail.com'],
            )
            msg.body = f"Hello Admin,\n\nA new user has just registered on the Agile Management Dashboard.\n\nBest Regards,\nAdmin Team"
            mail.send(msg)
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            print(f"Error: {e}")  # Log the error for debugging
            return redirect(url_for('auth.signup'))
    return render_template('register.html',title='Sign-up')
@auth.route('/redirect_reset_password')
def redirect_reset_password():
    return render_template('reset_password.html')

@auth.route('/reset_password',methods=['GET','POST'])
def reset_password():
    try:
        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm-password')
            if new_password != confirm_password:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('auth.reset_password'))
            # Update the user's password
            new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')  # Hash the new password
            User.query.filter_by(email=session['reset_email']).update({'password': new_password})
            db.session.commit()

            flash('Your password has been updated successfully.', 'success')
            return redirect(url_for('auth.login'))

        return render_template('reset_password.html')
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.forgot_password'))
@auth.route('/redirect_forgot_password')
def redirect_forgot_password():
    return render_template('forgot_password.html')
@auth.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    if request.method=="POST":
        email=request.form.get('email')
        if email == "" :
            flash('Please fill the field','danger')
            return redirect(url_for('auth.forgot_password'))
        else:
            users=User.query.filter_by(email=email).first()
            if users:
                otp = random.randint(100000, 999999)
                otp_storage[email] = {'otp': otp, 'expires': datetime.now() + timedelta(minutes=5)}
                print(mail.password)
                print(mail.sender)
                # Function to Send OTP Email
                mssg = Message(subject='Password Reset OTP',  recipients=[email])
                mssg.body=f'Your OTP for password reset is: {otp}. It will expire in 5 minutes.'
                try:
                    mail.send(mssg)
                    flash('Your otp has been sent to your email.', 'success')
                    return redirect(url_for('auth.verify_otp', email=email))
                except Exception as e:
                    print(f"Error sending email: {e}")
                    flash('Failed to send email. Please try again later.', 'danger')
                    return redirect(url_for('auth.forgot_password'))
            else:
                flash('Invalid Email','danger')
                return redirect(url_for('auth.forgot_password'))
    else:
        return render_template('forgot_password.html')
@auth.route('/verifyotp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        if email in otp_storage and int(request.form['otp']) == otp_storage[email]['otp']:
            session['reset_email'] = email
            return redirect(url_for('auth.reset_password'))
        flash('Invalid OTP.', 'danger')

    return render_template('verifyotp.html', email=email)
# Auth verify
@auth.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
          # check the admin approve your account are not
            is_approve=User.query.filter_by(id=user.id).first()
            # first return the is_approve:
            if is_approve.status == 0:
                flash('Your Account is not approved by Admin','danger')
                return redirect(url_for('auth.login'))
            elif is_approve.status == 2:
                flash("Your Account is rejected by Admin",'danger')
                return redirect(url_for('auth.login'))
            else:
                if user.mfa==1:
                    session['mfa_user_id'] = user.id
                    if not user.mfa_setup_complete:
                        qr_code = generate_mfa_qr_code(email, user.mfa_secret)
                        return render_template('enable_mfa.html', qr_code=qr_code,email=email,mfa_setup_complete=user.mfa_setup_complete)
                    else:
                        return render_template('enable_mfa.html', email=user.email,mfa_setup_complete=user.mfa_setup_complete)
                session['user_id']=user.id
                user.status=3
                session['last_activity'] = datetime.now().isoformat()
                flash('Login successful!', 'success')
                return redirect(url_for('auth.dashboard'))

        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html', title='Login')
@auth.route('/verify_mfa',methods=['GET','POST'])
def verify_mfa():
    if 'mfa_user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('auth.home'))
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        user_id = session['mfa_user_id']
        user = User.query.get(user_id)
        if user.mfa_secret:
            print(f"MFA Secret: {user.mfa_secret}")
            print(user_otp)
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(user_otp):
                if not user.mfa_setup_complete:
                    user.mfa_setup_complete = True
                    db.session.commit()
                session['user_id'] = user.id
                session.pop('mfa_user_id', None)
                session['last_activity'] = datetime.now().isoformat()
                flash('Succesfully Completed','success')
                return redirect(url_for('auth.dashboard'))
            else:
                flash("Invalid OTP.Please try again",'danger')
                return render_template('enable_mfa.html',title='Two-factor-authentication')
        else:
            flash('MFA is not enabled for this account.', 'warning')


    return render_template('enable_mfa.html',title='Two-factor-authentication')
# Auth dashboard
@auth.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.home'))

    # Fetch all projects from the database
    projects = Project.query.all()

    # Count projects by status for the chart
    pending_count = 0
    ongoing_count = 0
    completed_count = 0

    for project in projects:
        if project.status.lower() == 'not started':
            pending_count += 1
        elif project.status.lower() == 'completed':
            completed_count += 1
        else:
            ongoing_count += 1

    return render_template("user_dashboard.html",
                          title='dashboard',
                          projects=projects,
                          pending_count=pending_count,
                          ongoing_count=ongoing_count,
                          completed_count=completed_count)

# Auth logout
@auth.route('/logout', methods=['GET', 'POST'])
def logout():
    # Check if a user is in session (not admin)
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            # Update the logout timestamp
            user.logout = datetime.now()
            user.status=4
            db.session.commit()

        # Clear the user session
        session.pop('user_id', None)
        flash('Logged out successfully!', 'success')
    else:
        # Handle admin logout (no timestamp update)
        session.pop('admin_id', None)
        flash('Admin logged out successfully!', 'success')
    return redirect(url_for('auth.home'))
# Main routes
@main.route('/')
def index():
    return render_template('index2.html')

@main.route('/add_project_page')
def add_project_page():
    # Get all users for team member selection
    users = User.query.all()
    return render_template('auth/add_project.html', users=users)

@main.route('/add_project', methods=['POST'])
def add_project():
    try:
        data = request.get_json()

        # Create new project
        new_project = Project(
            project_id=data['projectId'],
            project_name=data['projectName'],
            project_description=data['projectDescription'],
            product_owner=data['ProductOwner'],
            development_team=data['devTeam'],
            start_date=datetime.strptime(data['startDate'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(data['endDate'], '%Y-%m-%d').date(),
            revised_end_date=datetime.strptime(data['revisedEndDate'], '%Y-%m-%d').date() if data['revisedEndDate'] else None,
            status=data['status']
        )

        db.session.add(new_project)
        db.session.flush()

        # Store sprints
        for sprint_data in data['sprints']:
            new_sprint = Sprint(
                project_id=new_project.project_id,
                sprint_number=sprint_data['sprint_number'],
                scrum_master=sprint_data['scrum_master'],
                start_date=datetime.strptime(sprint_data['start_date'], '%Y-%m-%d').date(),
                end_date=datetime.strptime(sprint_data['end_date'], '%Y-%m-%d').date(),
                velocity=0,
                status=data['status']
            )
            db.session.add(new_sprint)

        # Store user stories
        for story_data in data['userStories']:
            new_story = UserStory(
                project_id=new_project.project_id,
                team=story_data['team'],
                description=story_data['description'],
                story_point=story_data['points'],  # Changed from points to story_point
                status=data['status']
            )
            db.session.add(new_story)

        db.session.commit()

        # Send email notification
        send_project_notification(data)

        return jsonify({'success': True, 'message': 'Project created successfully'})

    except Exception as e:
        db.session.rollback()
        print(f"Error creating project: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@main.route('/projects', methods=['GET'])
def get_projects():
    projects = Project.query.all()
    return jsonify([project.to_dict() for project in projects])

def send_project_notification(data):
    try:
        selected_members = data['devTeam']
        product_owner = data['ProductOwner']

        subject = f"New Project Created: {data['projectName']}"
        body = f"""
        A new project has been created:
        - Project ID: {data['projectId']}
        - Project Name: {data['projectName']}
        - Description: {data['projectDescription']}
        - Product Owner: {product_owner}
        - Development Team: {', '.join(selected_members)}
        - Start Date: {data['startDate']}
        - End Date: {data['endDate']}
        """

        msg = Message(
            subject=subject,
            recipients=['teamofadm1n123@gmail.com'],  # Add your admin email
            body=body
        )
        mail.send(msg)

    except Exception as e:
        print(f"Error sending email notification: {str(e)}")
@main.route('/dashboard')
def dashboard():
    # Get all projects with their sprints and stories
    projects = Project.query.all()
    project_data = []

    for project in projects:
        sprints = Sprint.query.filter_by(project_id=project.project_id).all()
        sprint_data = []

        for sprint in sprints:
            stories = UserStory.query.filter_by(sprint_id=sprint.id).all()
            sprint_data.append({
                'id': sprint.id,
                'sprint_number': sprint.sprint_number,
                'scrum_master': sprint.scrum_master,
                'start_date': sprint.start_date.strftime('%Y-%m-%d'),
                'end_date': sprint.end_date.strftime('%Y-%m-%d'),
                'status': sprint.status,
                'stories': [story.to_dict() for story in stories]
            })

        project_data.append({
            'id': project.project_id,
            'name': project.project_name,
            'status': project.status,
            'sprints': sprint_data
        })

    return render_template('dashboard.html', projects=project_data)

@main.route('/project/<project_id>/edit', methods=['GET', 'POST'])
def edit_project_page(project_id):
    project = Project.query.filter_by(project_id=project_id).first()
    if not project:
        flash('Project not found.', 'danger')
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        try:
            # Get data from form
            project.project_name = request.form.get('projectName')
            project.project_description = request.form.get('projectDescription')
            project.product_owner = request.form.get('ProductOwner')
            # Handle development team (assuming it's a list of user IDs)
            dev_team_ids = request.form.getlist('devTeam')
            project.development_team = dev_team_ids  # Store IDs as JSON
            project.start_date = datetime.strptime(request.form.get('startDate'), '%Y-%m-%d').date()
            project.end_date = datetime.strptime(request.form.get('endDate'), '%Y-%m-%d').date()
            revised_end_date_str = request.form.get('revisedEndDate')
            project.revised_end_date = datetime.strptime(revised_end_date_str, '%Y-%m-%d').date() if revised_end_date_str else None
            project.status = request.form.get('status')

            # Update sprints (assuming you have a way to identify and update them)
            # This is a simplified example; adapt it to your actual form structure
            sprint_numbers = request.form.getlist('sprintNumber')
            sprint_scrum_masters = request.form.getlist('sprintScrumMaster')
            sprint_start_dates = request.form.getlist('sprintStartDate')
            sprint_end_dates = request.form.getlist('sprintEndDate')

            for i in range(len(sprint_numbers)):
                sprint_number = sprint_numbers[i]
                sprint = Sprint.query.filter_by(project_id=project_id, sprint_number=sprint_number).first()
                if sprint:
                    sprint.scrum_master = sprint_scrum_masters[i]
                    sprint.start_date = datetime.strptime(sprint_start_dates[i], '%Y-%m-%d').date()
                    sprint.end_date = datetime.strptime(sprint_end_dates[i], '%Y-%m-%d').date()

            # Update user stories
            story_ids = request.form.getlist('storyId')
            story_teams = request.form.getlist('userStoryTeam')
            story_descriptions = request.form.getlist('userStoryDescription')
            story_points = request.form.getlist('storyPoints')
            story_statuses = request.form.getlist('userStoryStatus')
            story_sprint_ids = request.form.getlist('userStorySprint')  # Get sprint IDs

            for i in range(len(story_ids)):
                story_id = story_ids[i]
                story = UserStory.query.get(story_id)
                if story:
                    story.team = story_teams[i]
                    story.description = story_descriptions[i]
                    story.story_point = int(story_points[i])
                    story.status = story_statuses[i]
                    story.sprint_id = story_sprint_ids[i]  # Assign sprint ID

            db.session.commit()
            flash('Project updated successfully!', 'success')
            return redirect(url_for('auth.dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating project: {str(e)}', 'danger')
            return render_template('auth/edit_project.html', project=project, users=User.query.all())

    # Get all users for team member selection
    users = User.query.all()
    teams = [{'name': 'IT Team 1'}, {'name': 'IT Team 2'}, {'name': 'IT Team 3'}, {'name': 'IT Team 4'}]
    sprints = Sprint.query.filter_by(project_id=project_id).all()  # Fetch sprints for the project
    return render_template('auth/edit_project.html', project=project, users=users, teams=teams, sprints=sprints)

@main.route('/project/<string:project_id>/view')
def view_project(project_id):
    project = Project.query.filter_by(project_id=project_id).first()
    if not project:
        flash('Project not found.', 'danger')
        return redirect(url_for('auth.dashboard'))

    # Project stats
    user_stories = UserStory.query.filter_by(project_id=project_id).all()
    total_stories = len(user_stories)
    completed_stories = len([story for story in user_stories if story.status.lower() == 'completed'])
    completion_percentage = (completed_stories / total_stories * 100) if total_stories > 0 else 0
    total_points = sum([story.story_point for story in user_stories])

    project_stats = {
        'total_stories': total_stories,
        'completed_stories': completed_stories,
        'completion_percentage': completion_percentage,
        'total_points': total_points
    }

    # Sprint details with calculated completion rates and velocities
    sprint_details = []
    sprints = Sprint.query.filter_by(project_id=project_id).order_by(Sprint.sprint_number).all()
    
    for sprint in sprints:
        sprint_stories = UserStory.query.filter_by(sprint_id=sprint.id).all()
        total_sprint_stories = len(sprint_stories)
        completed_sprint_stories = len([story for story in sprint_stories if story.status.lower() == 'completed'])
        completion_rate = (completed_sprint_stories / total_sprint_stories * 100) if total_sprint_stories > 0 else 0
        
        # Calculate sprint velocity (sum of story points from completed stories)
        velocity = sum([story.story_point for story in sprint_stories if story.status.lower() == 'completed'])
        
        sprint_details.append({
            'sprint_no': sprint.sprint_number,
            'start_date': sprint.start_date.strftime('%Y-%m-%d'),
            'end_date': sprint.end_date.strftime('%Y-%m-%d'),
            'velocity': velocity,
            'completion_rate': completion_rate
        })

    # Generate charts
    burndown_chart_url = generate_burndown_chart(project_id)
    burnup_chart_url = generate_burnup_chart(project_id)
    sprint_velocity_graph_url = generate_velocity_chart(sprint_details)

    # Team leaderboard
    leaderboard = []
    dev_team = project.development_team  # This is stored as JSON array
    
    for team_member in dev_team:
        member_stories = UserStory.query.filter_by(project_id=project_id, team=team_member).all()
        total_stories = len(member_stories)
        completed_stories = len([story for story in member_stories if story.status.lower() == 'completed'])
        points = sum([story.story_point for story in member_stories if story.status.lower() == 'completed'])

        if total_stories > 0:  # Only include team members with assigned stories
            leaderboard.append({
                'name': team_member,
                'points': points,
                'completed_stories': completed_stories,
                'total_stories': total_stories
            })

    # Sort leaderboard by points in descending order
    leaderboard = sorted(leaderboard, key=lambda x: x['points'], reverse=True)

    return render_template('auth/view_project.html',
                         project=project,
                         project_stats=project_stats,
                         sprint_details=sprint_details,
                         leaderboard=leaderboard,
                         burnup_chart_url=burnup_chart_url,
                         burndown_chart_url=burndown_chart_url,
                         sprint_velocity_graph_url=sprint_velocity_graph_url)

@main.route('/project/<string:project_id>/summary')
def summary(project_id):
    project = Project.query.filter_by(project_id=project_id).first()
    if not project:
        flash('Project not found.', 'danger')
        return redirect(url_for('auth.dashboard'))
    
    # Get project statistics
    user_stories = UserStory.query.filter_by(project_id=project_id).all()
    total_stories = len(user_stories)
    completed_stories = len([story for story in user_stories if story.status.lower() == 'completed'])
    completion_percentage = (completed_stories / total_stories * 100) if total_stories > 0 else 0
    total_points = sum([story.story_point for story in user_stories])

    project_stats = {
        'total_stories': total_stories,
        'completed_stories': completed_stories,
        'completion_percentage': completion_percentage,
        'total_points': total_points
    }

    return render_template('auth/project_summary.html', 
                         project=project, 
                         project_stats=project_stats)
