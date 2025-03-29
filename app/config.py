import os
from dotenv import load_dotenv
load_dotenv() 
class Config:
    # Don't share or commit .env file
    SECRET_KEY = os.getenv('SECRET_KEY', "4a8f3111fb4a9de6a6d050dd2b6ef98e")
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    
    
    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False 
    MAIL_USERNAME =os.getenv('MAIL_USERNAME','teamofadm1n123@gmail.com')
    MAIL_PASSWORD =os.getenv('MAIL_PASSWORD','wkmk oxaj rhov peup')
    MAIL_DEFAULT_SENDER =os.getenv('MAIL_USERNAME','teamofadm1n123@gmail.com')
    
    # Session Configuration
    SESSION_PERMANENT = False
    SESSION_TYPE = 'filesystem'
