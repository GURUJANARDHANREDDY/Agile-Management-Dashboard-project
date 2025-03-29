from . import db  # Import the shared db instance
from datetime import datetime
from sqlalchemy import DateTime
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(50), unique=True, nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    project_description = db.Column(db.Text, nullable=False)
    product_owner = db.Column(db.String(50), nullable=False)
    development_team = db.Column(db.JSON, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    revised_end_date = db.Column(db.Date, nullable=True)
    # Remove the sprints JSON column since we're using the Sprint model relationship
    status = db.Column(db.String(20), nullable=False, default='Not Started')

    # Add relationship to sprints
    sprints = db.relationship('Sprint', backref='project', lazy=True)

    def to_dict(self):
        return {
            'project_id': self.project_id,
            'project_name': self.project_name,
            'project_description': self.project_description,
            'product_owner': self.product_owner,
            'development_team': self.development_team,
            'start_date': self.start_date.strftime('%Y-%m-%d'),
            'end_date': self.end_date.strftime('%Y-%m-%d'),
            'revised_end_date': self.revised_end_date.strftime('%Y-%m-%d') if self.revised_end_date else None,
            'status': self.status,
            'sprints': self.sprints
        }

    def __repr__(self):
        """Representation of the Project object."""
        return f'<Project {self.project_id}: {self.project_name}>'


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender=db.Column(db.String(10),nullable=False)
    timestamp=db.Column(DateTime,default=datetime.now)
    logout=db.Column(DateTime,nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role=db.Column(db.String(20),nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)
    address=db.Column(db.String(50),nullable=False)
    mfa_secret=db.Column(db.String(16),nullable=True)
    mfa=db.Column(db.Integer,default=0,nullable=False)
    mfa_setup_complete = db.Column(db.Boolean, default=False)
    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.edu}","{self.username}","{self.status}","{self.address}")'


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        """Representation of the Admin object."""
        return f'<Admin {self.id}: {self.email}>'


class UserStory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(50), db.ForeignKey('project.project_id'), nullable=False)
    sprint_id = db.Column(db.Integer, db.ForeignKey('sprint.id'), nullable=True)
    team = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    story_point = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Not Started')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'sprint_id': self.sprint_id,
            'team': self.team,
            'description': self.description,
            'story_point': self.story_point,
            'status': self.status
        }


class Sprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(50), db.ForeignKey('project.project_id'), nullable=False)
    sprint_number = db.Column(db.Integer, nullable=False)
    scrum_master = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    velocity = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default='Not Started')

    # Add relationship to user stories
    user_stories = db.relationship('UserStory', backref='sprint', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'sprint_number': self.sprint_number,
            'scrum_master': self.scrum_master,
            'start_date': self.start_date.strftime('%Y-%m-%d'),
            'end_date': self.end_date.strftime('%Y-%m-%d'),
            'velocity': self.velocity,
            'status': self.status
        }

    def __repr__(self):
        return f'<Sprint {self.sprint_number} for Project {self.project_id}>'
