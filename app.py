from flask import Flask, render_template, request, jsonify, url_for, redirect, flash, session, Response, make_response
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, SelectField, PasswordField, BooleanField
from wtforms.validators import DataRequired, URL, Email, Length, EqualTo, ValidationError
import os
from datetime import datetime, timedelta
from model import PhishingDetectionModel
import joblib
import json
import re
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import uuid
import sqlite3
import socket
import ssl
import dns.resolver
import whois
import requests
from threading import Thread
import ipaddress
import time
from io import BytesIO
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

# Create database connection
def get_db_connection():
    conn = sqlite3.connect('phishguard.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        results TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        frequency TEXT NOT NULL,
        last_scan TIMESTAMP,
        next_scan TIMESTAMP,
        active BOOLEAN NOT NULL DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        api_key TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-should-be-very-long-and-secure'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_HISTORY'] = 20  # Maximum number of URLs to keep in history

# Initialize database
init_db()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the phishing detection model
phishing_model = PhishingDetectionModel()

# Force retrain the model with the new features
print("Training a new model with updated features...")
phishing_model.train(None)

# Add Jinja2 filters
@app.template_filter('from_json')
def from_json(value):
    """Convert a JSON string to a Python object."""
    if not value:
        return {}
    return json.loads(value)

# URL submission form
class URLForm(FlaskForm):
    url = StringField('URL to Check', validators=[DataRequired(), URL()])
    submit = SubmitField('Check URL')

# Batch URL submission form
class BatchURLForm(FlaskForm):
    file = StringField('Upload a file with URLs (one per line)')
    submit = SubmitField('Check URLs')

# Feedback form for improving model
class FeedbackForm(FlaskForm):
    feedback_type = SelectField('Was this prediction correct?', 
                               choices=[('correct', 'Yes, correct detection'), 
                                        ('false_positive', 'No, this is actually safe'), 
                                        ('false_negative', 'No, this is actually phishing')])
    comments = TextAreaField('Additional Comments')
    submit = SubmitField('Submit Feedback')

# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')
            
    def validate_email(self, email):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('That email is already registered. Please use a different one or login.')

# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# Network Security Scan Form
class NetworkScanForm(FlaskForm):
    target = StringField('Target (Domain, IP, or URL)', validators=[DataRequired()])
    scan_type = SelectField('Scan Type', choices=[
        ('basic', 'Basic Scan (DNS, WHOIS, Headers)'),
        ('ports', 'Port Scan (Common Ports)'),
        ('ssl', 'SSL Certificate Analysis'),
        ('headers', 'HTTP Headers Analysis'),
        ('full', 'Full Security Analysis')
    ])
    submit = SubmitField('Start Scan')

@app.route('/', methods=['GET', 'POST'])
def index():
    # If not logged in, show landing page with login prompt
    if 'user_id' not in session:
        flash('You must log in to use this feature.', 'warning')
        return redirect(url_for('login'))
        
    form = URLForm()
    batch_form = BatchURLForm()
    feedback_form = FeedbackForm()
    result = None
    
    # Initialize session history if it doesn't exist
    if 'history' not in session:
        session['history'] = []
    
    if request.method == 'POST':
        # Get URL from form data directly
        url = request.form.get('url')
        
        if not url:
            flash('Please enter a URL to check.', 'danger')
            return render_template('index.html', form=form, batch_form=batch_form, 
                          feedback_form=feedback_form, result=None, 
                          history=session.get('history', []), phishing_types=get_phishing_types())
        
        # Ensure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url
        
        try:
            # Check if URL is potentially dangerous before even analyzing
            if is_obviously_phishing(url):
                prediction = {
                    'is_phishing': True,
                    'probability': 1.0,
                    'features': {'obvious_phishing': True}
                }
                result = format_result(url, prediction)
            else:
                # Get prediction from model
                prediction = phishing_model.predict(url)
                result = format_result(url, prediction)
            
            # Add to history (will be stored in session)
            add_to_history(result)
            
            # Save to database if user is logged in
            if 'user_id' in session:
                conn = get_db_connection()
                conn.execute('INSERT INTO scan_history (user_id, target, scan_type, results) VALUES (?, ?, ?, ?)',
                            (session['user_id'], url, 'phishing', json.dumps(result)))
                conn.commit()
                conn.close()
                
        except Exception as e:
            print(f"Error checking URL: {str(e)}")
            flash(f"Error checking URL: {str(e)}", "danger")
    
    # Get history from session
    history = session.get('history', [])
    
    return render_template('index.html', form=form, batch_form=batch_form, 
                          feedback_form=feedback_form, result=result, 
                          history=history, phishing_types=get_phishing_types())

@app.route('/api/check', methods=['POST'])
def api_check():
    # Get URL from request
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL not provided'}), 400
    
    url = data['url']
    
    # Ensure URL has scheme
    if not url.startswith('http'):
        url = 'http://' + url
    
    # Check for obviously malicious URLs
    if is_obviously_phishing(url):
        result = {
            'url': url,
            'is_phishing': True,
            'probability': 1.0,
            'message': 'This URL shows strong indicators of a phishing attempt.',
            'features': {'obvious_phishing': True},
            'width_class': 'w-100',
            'check_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'id': str(uuid.uuid4())
        }
    else:
        # Get prediction
        prediction = phishing_model.predict(url)
        
        # Format result
        result = {
            'url': url,
            'is_phishing': prediction['is_phishing'],
            'probability': prediction['probability'],
            'message': get_message(prediction),
            'features': prediction['features'],
            'width_class': get_width_class(prediction['probability']),
            'check_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'id': str(uuid.uuid4())
        }
    
    return jsonify(result)

@app.route('/batch', methods=['POST'])
def batch_upload():
    # Check if file was uploaded
    if 'file' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    # Check if file is empty
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    # Save file
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Process file
    results = []
    with open(file_path, 'r') as f:
        urls = f.readlines()
        
        for url in urls:
            url = url.strip()
            if url:
                # Ensure URL has scheme
                if not url.startswith('http'):
                    url = 'http://' + url
                
                # Get prediction
                prediction = phishing_model.predict(url)
                
                # Format result
                results.append({
                    'url': url,
                    'is_phishing': prediction['is_phishing'],
                    'probability': prediction['probability'],
                    'message': get_message(prediction),
                    'width_class': get_width_class(prediction['probability']),
                    'check_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'id': str(uuid.uuid4())
                })
    
    return render_template('batch_results.html', results=results)

@app.route('/feedback/<result_id>', methods=['POST'])
def submit_feedback(result_id):
    """Submit feedback about prediction accuracy to improve the model."""
    form = FeedbackForm()
    if form.validate_on_submit():
        # In a real app, you'd store this feedback and use it to improve the model
        feedback_type = form.feedback_type.data
        comments = form.comments.data
        
        # Just a placeholder - in production you would store feedback
        flash('Thank you for your feedback! It helps us improve our detection system.', 'success')
    
    return redirect(url_for('index'))

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear the URL checking history from session."""
    session['history'] = []
    flash('History cleared', 'info')
    return redirect(url_for('index'))

@app.route('/export_report/<result_id>', methods=['GET'])
def export_report(result_id):
    """Generate a detailed report for the given check result."""
    # In a real app, you'd retrieve the specific result
    # For now, we'll find it in the history
    history = session.get('history', [])
    result = next((item for item in history if item.get('id') == result_id), None)
    
    if not result:
        flash('Report not found', 'danger')
        return redirect(url_for('index'))
    
    return render_template('report.html', result=result, phishing_types=get_phishing_types())

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/education')
def education():
    """Educational page about phishing tactics and prevention."""
    return render_template('education.html', phishing_types=get_phishing_types())

@app.route('/batch_check', methods=['GET', 'POST'], endpoint='batch_process_endpoint')
def batch_process():
    """Handle batch URL checking from file upload."""
    # Require login
    if 'user_id' not in session:
        flash('You must log in to use batch scanning features.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if request has either 'urlfile' (from batch_check.html) or 'file' (from index.html)
        file_param = None
        if 'urlfile' in request.files:
            file_param = 'urlfile'
        elif 'file' in request.files:
            file_param = 'file'
            
        if not file_param:
            flash('No file uploaded', 'error')
            return redirect(url_for('batch_process_endpoint'))
        
        file = request.files[file_param]
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('batch_process_endpoint'))
        
        if not file.filename.endswith('.txt'):
            flash('Please upload a text file', 'error')
            return redirect(url_for('batch_process_endpoint'))
        
        try:
            # Read URLs from file
            urls = [line.strip() for line in file.readlines() if line.strip()]
            if not urls:
                flash('No URLs found in file', 'error')
                return redirect(url_for('batch_process_endpoint'))
            
            # Process each URL
            results = []
            for url in urls:
                try:
                    # Validate URL
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    
                    # Check URL
                    result = check_url(url)
                    result['url'] = url  # Add original URL to result
                    results.append(result)
                    
                    # Add to history
                    add_to_history(result)
                    
                    # Also save to database
                    conn = get_db_connection()
                    conn.execute('INSERT INTO scan_history (user_id, target, scan_type, results) VALUES (?, ?, ?, ?)',
                                (session['user_id'], url, 'batch_phishing', json.dumps(result)))
                    conn.commit()
                    conn.close()
                    
                except Exception as e:
                    results.append({
                        'url': url,
                        'error': str(e),
                        'is_phishing': None,
                        'probability': None
                    })
            
            return render_template('batch_check.html', results=results)
            
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')
            return redirect(url_for('batch_process_endpoint'))
    
    return render_template('batch_check.html')

@app.route('/export_batch_report')
def export_batch_report():
    """Export batch check results as CSV."""
    if 'history' not in session:
        flash('No results to export', 'error')
        return redirect(url_for('batch_process_endpoint'))
    
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['URL', 'Risk Assessment', 'Probability', 'Check Date'])
    
    # Write data
    for result in session['history']:
        writer.writerow([
            result['url'],
            'Phishing' if result['is_phishing'] else 'Safe',
            f"{result['probability']:.2%}",
            result['check_date']
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=phishing_check_results.csv'}
    )

def is_obviously_phishing(url):
    """Check for obviously malicious URLs before model prediction."""
    # Check for extremely suspicious patterns
    obvious_patterns = [
        r'paypal.*\.(tk|xyz|ml|ga|cf|gq)',
        r'bank.*\.(info|xyz|site|online)',
        r'verify.*\.(xyz|ml|tk|ga|cf|gq)',
        r'secure.*login.*\.(cc|xyz|online)',
        r'\d+\.\d+\.\d+\.\d+/login',
        r'password.*reset.*\.(info|xyz|tk|ml|ga|cf|gq)',
        r'account.*verify.*\.(com|net|org|info|site)',
        r'signin.*\.(tk|ml|ga|cf|gq)',
        r'update.*account.*\.(info|xyz|online)',
        r'auth.*\.(xyz|ml|ga|cf|gq)',
        r'wallet.*verify.*\.(com|net)',
        r'manage.*billing.*\.(info|site|xyz)',
        r'\.ru/(?:login|account|secure)',
        r'\.cn/(?:login|account|secure)'
    ]
    
    # Check if it's a well-known legitimate domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Expanded list of known legitimate domains
    known_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com', 
        'microsoft.com', 'youtube.com', 'netflix.com', 'twitter.com',
        'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'reddit.com', 'bbc.com', 'cnn.com', 'nytimes.com',
        'ebay.com', 'walmart.com', 'etsy.com', 'paypal.com', 'spotify.com',
        'yahoo.com', 'twitch.tv', 'adobe.com', 'dropbox.com', 'salesforce.com',
        'slack.com', 'zoom.us', 'pinterest.com', 'tumblr.com', 'vimeo.com',
        'whatsapp.com', 'telegram.org', 'signal.org', 'discord.com', 'shopify.com',
        'office.com', 'live.com', 'outlook.com', 'gmail.com', 'hotmail.com',
        'protonmail.com', 'mail.com', 'icloud.com', 'cloudflare.com', 'aws.amazon.com',
        'azure.microsoft.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'medium.com',
        'quora.com', 'forbes.com', 'bloomberg.com', 'reuters.com', 'wordpress.com'
    ]
    
    # If it's a known domain, it's not phishing
    if any(domain.endswith(d) or domain == d for d in known_domains):
        return False
    
    # Heuristic checks for suspicious URL patterns
    suspicious_indicators = [
        domain.count('.') > 3,  # Too many subdomains
        '@' in url,             # @ symbol in URL is suspicious
        domain.count('-') > 2,  # Too many hyphens in domain
        re.search(r'\d{5,}', domain),  # Long number sequences in domain
        re.search(r'[a-zA-Z0-9]\.[a-zA-Z0-9]\.', domain)  # Suspicious subdomain pattern
    ]
    
    # If it has multiple suspicious indicators
    if sum(suspicious_indicators) > 2:
        return True
    
    # If it matches an obvious phishing pattern
    for pattern in obvious_patterns:
        if re.search(pattern, url.lower()):
            return True
    
    return False

def get_message(prediction):
    """Get a human-readable message based on prediction results."""
    probability = prediction['probability']
    features = prediction['features']
    
    # Determine the specific type of phishing attempt
    phishing_type = determine_phishing_type(features, prediction['is_phishing'])
    
    if prediction['is_phishing']:
        if probability > 0.9:
            return f"High confidence this is a phishing URL ({phishing_type}). Do not visit this site!"
        elif probability > 0.7:
            return f"This URL shows strong signs of being a phishing attempt ({phishing_type}). Proceed with caution."
        else:
            return f"This URL has some characteristics of phishing sites ({phishing_type}). Be careful."
    else:
        if probability < 0.1:
            return "This URL appears to be legitimate with high confidence."
        elif probability < 0.3:
            return "This URL likely legitimate, but exercise normal caution."
        else:
            return "This URL may be legitimate but has some suspicious characteristics. Use caution."

def determine_phishing_type(features, is_phishing):
    """Determine the specific type of phishing based on features."""
    if not is_phishing:
        return "Legitimate"
    
    # Check for different types of phishing attacks
    if features.get('has_ip', False):
        return "IP-based phishing"
    elif features.get('brand_in_subdomain', False):
        return "Brand impersonation"
    elif features.get('is_shortened', False):
        return "URL shortener phishing"
    elif features.get('has_suspicious_tld', False):
        return "Suspicious TLD phishing"
    elif features.get('has_redirection', False):
        return "Redirection-based phishing"
    elif features.get('numbers_in_domain', 0) > 2:
        return "Typosquatting phishing"
    elif features.get('has_at_symbol', False):
        return "URL obfuscation phishing"
    elif features.get('excessive_slashes', False):
        return "Path manipulation phishing"
    elif features.get('domain_is_numeric', False):
        return "Numeric domain phishing"
    else:
        return "Generic phishing"

def get_width_class(probability):
    """Convert probability to a CSS width class."""
    p = int(probability * 10) * 10
    return f"w-{p}"

# Custom Jinja filter to extract phishing type from message
@app.template_filter('extract_phishing_type')
def extract_phishing_type(message):
    """Extract the phishing type from a result message."""
    import re
    match = re.search(r'\(([^)]+)\)', message)
    return match.group(1) if match else "Generic phishing"

# Custom Jinja filter to parse URLs
@app.template_filter('urlparse')
def url_parse_filter(url):
    """Parse a URL and return its components."""
    return urlparse(url)

def add_to_history(result):
    """Add a URL check result to the history in session."""
    history = session.get('history', [])
    
    # Add new result at the beginning
    history.insert(0, result)
    
    # Limit history size
    if len(history) > app.config['MAX_HISTORY']:
        history = history[:app.config['MAX_HISTORY']]
    
    session['history'] = history

def get_phishing_types():
    """Return information about different phishing types for education."""
    return {
        "Brand impersonation": {
            "description": "Attackers create websites that look like trusted brands to steal credentials.",
            "indicators": ["Slight misspellings of known domains", "Brand names in subdomains", "Visual imitation of legitimate sites"],
            "example": "amazon-account-verify.com instead of amazon.com",
            "prevention": "Always check the URL carefully before entering credentials. Look for the correct domain name."
        },
        "Typosquatting phishing": {
            "description": "Registering domains that are common typos of popular websites.",
            "indicators": ["Similar-looking domains with slight misspellings", "Replacing letters with numbers (o→0, l→1)"],
            "example": "g00gle.com instead of google.com",
            "prevention": "Double-check URLs before visiting, especially when typing them manually."
        },
        "URL shortener phishing": {
            "description": "Using URL shorteners to hide the actual destination of malicious links.",
            "indicators": ["Short URLs from bit.ly, tinyurl, etc.", "Cannot see the actual destination before clicking"],
            "example": "bit.ly/suspicious-link",
            "prevention": "Use URL preview services to see the actual destination before clicking shortened links."
        },
        "IP-based phishing": {
            "description": "Using raw IP addresses instead of domain names to host phishing pages.",
            "indicators": ["URLs containing IP addresses instead of domain names", "Login forms on numeric addresses"],
            "example": "http://192.168.1.1/login.php",
            "prevention": "Be extremely cautious of URLs that use IP addresses instead of domain names."
        },
        "URL obfuscation phishing": {
            "description": "Using special characters to manipulate how URLs appear or function.",
            "indicators": ["@ symbols in URLs", "Encoded characters", "Data URI schemes"],
            "example": "https://login@malicious-site.com",
            "prevention": "Check the entire URL for unusual characters or encoding."
        },
        "Generic phishing": {
            "description": "General phishing attempts without specific techniques.",
            "indicators": ["Suspicious words", "Generic domain names", "Request for sensitive information"],
            "example": "secure-login-verify.com",
            "prevention": "Be wary of any unexpected requests for information, even if the site seems legitimate."
        }
    }

def check_url(url):
    """Check if a URL is phishing or legitimate and return formatted results."""
    # Check if URL is potentially dangerous before analyzing
    if is_obviously_phishing(url):
        result = {
            'url': url,
            'is_phishing': True,
            'probability': 1.0,
            'message': 'This URL shows strong indicators of a phishing attempt.',
            'features': {'obvious_phishing': True},
            'width_class': 'w-100',
            'check_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'id': str(uuid.uuid4())
        }
    else:
        # Get prediction from model
        prediction = phishing_model.predict(url)
        
        # Format result
        result = {
            'url': url,
            'is_phishing': prediction['is_phishing'],
            'probability': prediction['probability'],
            'message': get_message(prediction),
            'features': prediction['features'],
            'width_class': get_width_class(prediction['probability']),
            'check_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'id': str(uuid.uuid4())
        }
    
    return result

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    (form.username.data, form.email.data, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (form.email.data,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], form.password.data):
            session['user_id'] = user['id']
            session['username'] = user['username']
            next_page = request.args.get('next')
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    # Redirect to login if not authenticated
    if 'user_id' not in session:
        flash('You must log in to view your dashboard.', 'warning')
        return redirect(url_for('login'))
    
    # Get user data
    conn = get_db_connection()
    user_id = session['user_id']
    
    # Get basic user info
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    # Get scan history with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    # Get total count for pagination
    total_scans = conn.execute('SELECT COUNT(*) FROM scan_history WHERE user_id = ?', 
                              (user_id,)).fetchone()[0]
    
    # Get recent scans for this page
    recent_scans = conn.execute(
        'SELECT * FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
        (user_id, per_page, offset)
    ).fetchall()
    
    # Get scheduled scans
    scheduled_scans = conn.execute(
        'SELECT * FROM scheduled_scans WHERE user_id = ? AND active = 1 ORDER BY next_scan ASC',
        (user_id,)
    ).fetchall()
    
    # Get API keys
    api_keys = conn.execute(
        'SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    
    # Calculate security statistics
    high_risk_scans = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND json_extract(results, '$.risk_score') > 70", 
        (user_id,)
    ).fetchone()[0]
    
    medium_risk_scans = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND json_extract(results, '$.risk_score') BETWEEN 40 AND 70", 
        (user_id,)
    ).fetchone()[0]
    
    low_risk_scans = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND json_extract(results, '$.risk_score') < 40", 
        (user_id,)
    ).fetchone()[0]
    
    # Calculate scan type statistics
    scan_types = conn.execute(
        "SELECT scan_type, COUNT(*) as count FROM scan_history WHERE user_id = ? GROUP BY scan_type",
        (user_id,)
    ).fetchall()
    
    # Get recent phishing detection results
    phishing_results = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? AND scan_type = 'phishing' ORDER BY created_at DESC LIMIT 5",
        (user_id,)
    ).fetchall()
    
    # Close the database connection
    conn.close()
    
    # Calculate pagination info
    total_pages = (total_scans + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    # Dashboard data for charts
    risk_data = {
        'high': high_risk_scans,
        'medium': medium_risk_scans,
        'low': low_risk_scans
    }
    
    scan_type_data = {item['scan_type']: item['count'] for item in scan_types}
    
    return render_template('dashboard.html', 
                          user=user,
                          recent_scans=recent_scans,
                          scheduled_scans=scheduled_scans,
                          api_keys=api_keys,
                          high_risk_scans=high_risk_scans,
                          medium_risk_scans=medium_risk_scans,
                          low_risk_scans=low_risk_scans,
                          total_scans=total_scans,
                          page=page,
                          total_pages=total_pages,
                          has_prev=has_prev,
                          has_next=has_next,
                          phishing_results=phishing_results,
                          risk_data=risk_data,
                          scan_type_data=scan_type_data)

@app.route('/network_analyzer', methods=['GET', 'POST'])
def network_analyzer():
    # Redirect to login if not authenticated
    if 'user_id' not in session:
        flash('You must log in to use the Network Analyzer.', 'warning')
        return redirect(url_for('login'))
    
    form = NetworkScanForm()
    
    if form.validate_on_submit():
        target = form.target.data
        scan_type = form.scan_type.data
        
        # Check if target is valid
        if not target:
            flash('Please enter a valid target.', 'danger')
            return redirect(url_for('network_analyzer'))
        
        try:
            # Perform the scan based on type
            result = perform_network_scan(target, scan_type)
            
            # Calculate risk score
            risk_score = calculate_risk_score(result)
            result['risk_score'] = risk_score
            
            # Generate recommendations
            recommendations = generate_recommendations(result)
            result['recommendations'] = recommendations
            
            # Add scan timestamp
            result['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Add unique ID for the scan
            scan_id = str(uuid.uuid4())
            result['scan_id'] = scan_id
            
            # Save result to database
            conn = get_db_connection()
            user_id = session.get('user_id')
            save_scan_to_db(conn, user_id, target, scan_type, json.dumps(result))
            conn.close()
            
            # For AJAX requests, return JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'redirect': url_for('scan_report', scan_id=scan_id)
                })
            
            # For regular form submissions, redirect to the report page
            return redirect(url_for('scan_report', scan_id=scan_id))
            
        except Exception as e:
            app.logger.error(f"Scan error: {str(e)}")
            flash(f'Error performing scan: {str(e)}', 'danger')
            
            # For AJAX requests, return error JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
                
            return redirect(url_for('network_analyzer'))
    
    return render_template('network_analyzer.html', form=form)

def save_scan_to_db(conn, user_id, target, scan_type, result):
    """Save scan results to database and return the scan_id"""
    try:
        cursor = conn.execute(
            'INSERT INTO scan_history (user_id, target, scan_type, results) VALUES (?, ?, ?, ?)',
            (user_id, target, scan_type, result)
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"Error saving scan to database: {str(e)}")
        conn.rollback()
        return None

@app.route('/scan_report/<int:scan_id>')
def scan_report(scan_id):
    """Display a specific scan report by ID"""
    # Redirect to login if not authenticated
    if 'user_id' not in session:
        flash('You must log in to view scan reports.', 'warning')
        return redirect(url_for('login'))
    
    # Get the scan from database
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scan_history WHERE id = ? AND user_id = ?', 
                       (scan_id, session['user_id'])).fetchone()
    conn.close()
    
    if not scan:
        flash('Scan report not found or you do not have permission to view it.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Parse the JSON results
    try:
        result = json.loads(scan['results'])
        
        # Update the timestamp to be more readable
        if 'timestamp' in result:
            timestamp = datetime.strptime(result['timestamp'], '%Y-%m-%d %H:%M:%S')
            result['human_timestamp'] = timestamp.strftime('%B %d, %Y at %I:%M %p')
        
        # Add the scan ID to the result for the template
        result['scan_id'] = scan_id
        
        return render_template('scan_report.html', result=result, scan=scan)
    except Exception as e:
        flash(f'Error displaying scan report: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/export_pdf_report/<int:scan_id>')
def export_pdf_report(scan_id):
    """Generate a PDF report for a specific scan"""
    # Redirect to login if not authenticated
    if 'user_id' not in session:
        flash('You must log in to export PDF reports.', 'warning')
        return redirect(url_for('login'))
    
    # Get the scan from database
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scan_history WHERE id = ? AND user_id = ?', 
                       (scan_id, session['user_id'])).fetchone()
    conn.close()
    
    if not scan:
        flash('Scan report not found or you do not have permission to view it.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Parse the JSON results
    try:
        result = json.loads(scan['results'])
        
        # Create the PDF using ReportLab
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
        from reportlab.lib.units import inch
        from io import BytesIO
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Add custom styles
        styles.add(ParagraphStyle(name='Title',
                                 parent=styles['Heading1'],
                                 fontSize=18,
                                 spaceAfter=12))
        styles.add(ParagraphStyle(name='SectionHeading',
                                 parent=styles['Heading2'],
                                 fontSize=14,
                                 spaceBefore=12,
                                 spaceAfter=6))
        styles.add(ParagraphStyle(name='SubHeading',
                                 parent=styles['Heading3'],
                                 fontSize=12,
                                 spaceBefore=6,
                                 spaceAfter=6))
        
        # Content elements
        elements = []
        
        # Title
        elements.append(Paragraph(f"Security Scan Report - {result['target']}", styles['Title']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Create metadata table
        metadata = [
            ["Target", result['target']],
            ["Scan Type", result['scan_type'].capitalize()],
            ["Scan Date", result.get('timestamp', 'N/A')],
            ["Report ID", f"SCAN-{scan_id}"]
        ]
        
        t = Table(metadata, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.2*inch))
        
        # Risk Assessment
        elements.append(Paragraph("Risk Assessment", styles['SectionHeading']))
        risk_score = result.get('risk_score', 0)
        risk_color = colors.green
        risk_level = "Low"
        
        if risk_score > 70:
            risk_color = colors.red
            risk_level = "High"
        elif risk_score > 40:
            risk_color = colors.orange
            risk_level = "Medium"
        
        risk_data = [
            ["Risk Score", f"{risk_score}%"],
            ["Risk Level", risk_level]
        ]
        
        t = Table(risk_data, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.2*inch))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", styles['SectionHeading']))
        
        if risk_score > 70:
            summary = "This scan detected HIGH RISK security issues that require immediate attention. The target may be vulnerable to attacks or data breaches."
        elif risk_score > 40:
            summary = "This scan detected MEDIUM RISK security issues that should be addressed. While not critical, these issues could potentially be exploited."
        else:
            summary = "This scan detected LOW RISK security issues. The target appears to have good security practices in place, with only minor improvements suggested."
        
        elements.append(Paragraph(summary, styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Add findings sections based on scan type
        if 'findings' in result:
            findings = result['findings']
            
            # Basic Information (DNS, WHOIS)
            if 'basic' in findings:
                elements.append(Paragraph("Basic Information", styles['SectionHeading']))
                
                # DNS Records
                if 'dns' in findings['basic']:
                    elements.append(Paragraph("DNS Records", styles['SubHeading']))
                    dns = findings['basic']['dns']
                    
                    # A Records
                    if 'a_records' in dns and dns['a_records']:
                        elements.append(Paragraph("A Records:", styles['Bullet']))
                        for record in dns['a_records']:
                            elements.append(Paragraph(f"• {record}", styles['Normal']))
                        elements.append(Spacer(1, 0.1*inch))
                    
                    # MX Records
                    if 'mx_records' in dns and dns['mx_records']:
                        elements.append(Paragraph("MX Records:", styles['Bullet']))
                        for record in dns['mx_records']:
                            elements.append(Paragraph(f"• {record}", styles['Normal']))
                        elements.append(Spacer(1, 0.1*inch))
                    
                    # NS Records
                    if 'ns_records' in dns and dns['ns_records']:
                        elements.append(Paragraph("NS Records:", styles['Bullet']))
                        for record in dns['ns_records']:
                            elements.append(Paragraph(f"• {record}", styles['Normal']))
                        elements.append(Spacer(1, 0.1*inch))
                
                # WHOIS Information
                if 'whois' in findings['basic']:
                    elements.append(Paragraph("WHOIS Information", styles['SubHeading']))
                    whois = findings['basic']['whois']
                    
                    whois_data = []
                    for key, value in whois.items():
                        if key != 'raw' and value:  # Skip raw data and empty values
                            whois_data.append([key.replace('_', ' ').title(), str(value)])
                    
                    if whois_data:
                        t = Table(whois_data, colWidths=[2*inch, 4*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                            ('BOX', (0, 0), (-1, -1), 1, colors.black),
                            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('PADDING', (0, 0), (-1, -1), 6),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 0.2*inch))
            
            # Port Scan
            if 'ports' in findings:
                elements.append(Paragraph("Port Scan Results", styles['SectionHeading']))
                
                port_data = [["Port", "Service", "Status"]]
                for port, info in findings['ports'].items():
                    port_data.append([port, info.get('service', 'Unknown'), info.get('status', 'Unknown')])
                
                if len(port_data) > 1:  # If we have data beyond headers
                    t = Table(port_data)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('BOX', (0, 0), (-1, -1), 1, colors.black),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t)
                    elements.append(Spacer(1, 0.2*inch))
                else:
                    elements.append(Paragraph("No open ports detected", styles['Normal']))
            
            # SSL Certificate
            if 'ssl' in findings:
                elements.append(Paragraph("SSL Certificate Analysis", styles['SectionHeading']))
                ssl = findings['ssl']
                
                ssl_data = []
                for key, value in ssl.items():
                    if key != 'raw' and value is not None:  # Skip raw data and None values
                        if isinstance(value, bool):
                            value = "Yes" if value else "No"
                        ssl_data.append([key.replace('_', ' ').title(), str(value)])
                
                if ssl_data:
                    t = Table(ssl_data, colWidths=[2*inch, 4*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('BOX', (0, 0), (-1, -1), 1, colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t)
                    elements.append(Spacer(1, 0.2*inch))
            
            # HTTP Headers
            if 'headers' in findings:
                elements.append(Paragraph("HTTP Headers Analysis", styles['SectionHeading']))
                headers = findings['headers']
                
                if 'security_headers' in headers:
                    elements.append(Paragraph("Security Headers", styles['SubHeading']))
                    sec_headers = headers['security_headers']
                    
                    header_data = [["Header", "Present", "Value"]]
                    for header, info in sec_headers.items():
                        present = "Yes" if info.get('present', False) else "No"
                        value = info.get('value', 'N/A')
                        header_data.append([header, present, value])
                    
                    t = Table(header_data)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('BOX', (0, 0), (-1, -1), 1, colors.black),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t)
                    elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        if 'recommendations' in result:
            elements.append(Paragraph("Security Recommendations", styles['SectionHeading']))
            
            for rec in result['recommendations']:
                severity = rec.get('severity', 'low').capitalize()
                title = rec.get('title', 'No title')
                description = rec.get('description', 'No description')
                
                severity_color = colors.green
                if severity.lower() == 'high':
                    severity_color = colors.red
                elif severity.lower() == 'medium':
                    severity_color = colors.orange
                
                elements.append(Paragraph(f"{severity} Priority: {title}", styles['SubHeading']))
                elements.append(Paragraph(description, styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
        
        # Footer
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph(f"Report generated by PhishGuard on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        
        # Get the PDF data and return it
        pdf_data = buffer.getvalue()
        buffer.close()
        
        filename = f"security_scan_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        
        response = make_response(pdf_data)
        response.headers.set('Content-Disposition', f'attachment; filename={filename}')
        response.headers.set('Content-Type', 'application/pdf')
        
        return response
        
    except Exception as e:
        flash(f'Error generating PDF report: {str(e)}', 'danger')
        return redirect(url_for('scan_report', scan_id=scan_id))

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def perform_network_scan(target, scan_type, requests_timeout=15):
    """
    Perform a network security scan based on the specified scan type
    """
    print(f"Starting network scan for {target} with scan type {scan_type}")
    
    # Validate scan_type as a precaution
    valid_scan_types = ['basic', 'ports', 'ssl', 'headers', 'full']
    if scan_type not in valid_scan_types:
        scan_type = 'basic'
        print(f"Invalid scan type provided, defaulting to basic scan")
    
    result = {
        'target': target,
        'scan_type': scan_type,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'findings': {}
    }
    
    # Parse the target
    try:
        # Check if this is an IP address
        if is_valid_ip(target):
            domain = target
            print(f"Target is an IP address: {domain}")
        else:
            # Parse as URL if not an IP
            parsed_url = urlparse(target)
            
            # Handle both domain.com and http://domain.com cases
            if parsed_url.netloc:
                domain = parsed_url.netloc
            else:
                domain = parsed_url.path
                
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            print(f"Parsed domain: {domain}")
    except Exception as e:
        print(f"Error parsing URL: {str(e)}")
        domain = target
    
    # Basic scan components - always included
    try:
        print("Starting basic scan...")
        result['findings']['basic'] = perform_basic_scan(domain)
        print("Basic scan completed")
    except Exception as e:
        print(f"Error in basic scan: {str(e)}")
        result['findings']['basic'] = {'error': f"Basic scan failed: {str(e)}"}
    
    # Specific scan types
    if scan_type == 'ports' or scan_type == 'full':
        try:
            print("Starting port scan...")
            result['findings']['ports'] = perform_port_scan(domain)
            print("Port scan completed")
        except Exception as e:
            print(f"Error in port scan: {str(e)}")
            result['findings']['ports'] = {'error': f"Port scan failed: {str(e)}"}
    
    if scan_type == 'ssl' or scan_type == 'full':
        try:
            print("Starting SSL scan...")
            result['findings']['ssl'] = perform_ssl_scan(domain)
            print("SSL scan completed")
        except Exception as e:
            print(f"Error in SSL scan: {str(e)}")
            result['findings']['ssl'] = {'error': f"SSL scan failed: {str(e)}"}
    
    if scan_type == 'headers' or scan_type == 'full':
        try:
            # For headers scan, use the original target URL
            print("Starting headers scan...")
            result['findings']['headers'] = perform_headers_scan(target, requests_timeout)
            print("Headers scan completed")
        except Exception as e:
            print(f"Error in headers scan: {str(e)}")
            result['findings']['headers'] = {'error': f"Headers scan failed: {str(e)}"}
    
    # Calculate risk score
    try:
        result['risk_score'] = calculate_risk_score(result['findings'])
        result['recommendations'] = generate_recommendations(result['findings'])
    except Exception as e:
        print(f"Error calculating risk score: {str(e)}")
        result['risk_score'] = 50  # Default to medium risk on error
        result['recommendations'] = [{'title': 'Error in analysis', 'description': f'Error: {str(e)}', 'severity': 'medium'}]
    
    return result

def perform_basic_scan(domain):
    """Basic scan including DNS, WHOIS, and domain information"""
    print(f"Starting basic scan for domain: {domain}")
    
    results = {
        'dns': {},
        'whois': {},
        'ip': None
    }
    
    # DNS Lookups
    try:
        print("Attempting DNS lookups...")
        # A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results['dns']['a_records'] = [record.to_text() for record in a_records]
            results['ip'] = results['dns']['a_records'][0] if results['dns']['a_records'] else None
            print(f"A records found: {results['dns'].get('a_records', [])}")
        except Exception as a_e:
            print(f"A record lookup failed: {str(a_e)}")
            results['dns']['a_records'] = []
            # Try to get IP through socket as fallback
            try:
                results['ip'] = socket.gethostbyname(domain)
                results['dns']['a_records'] = [results['ip']]
                print(f"Got IP through socket: {results['ip']}")
            except:
                pass
        
        # MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['dns']['mx_records'] = [record.to_text() for record in mx_records]
        except Exception as mx_e:
            print(f"MX record lookup failed: {str(mx_e)}")
            results['dns']['mx_records'] = []
        
        # NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results['dns']['ns_records'] = [record.to_text() for record in ns_records]
        except Exception as ns_e:
            print(f"NS record lookup failed: {str(ns_e)}")
            results['dns']['ns_records'] = []
        
        # TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results['dns']['txt_records'] = [record.to_text().replace('"', '') for record in txt_records]
        except Exception as txt_e:
            print(f"TXT record lookup failed: {str(txt_e)}")
            results['dns']['txt_records'] = []
            
        # Check for SPF and DMARC
        results['dns']['has_spf'] = any('v=spf1' in txt.lower() for txt in results['dns'].get('txt_records', []))
        results['dns']['has_dmarc'] = any('v=dmarc1' in txt.lower() for txt in results['dns'].get('txt_records', []))
        print("DNS lookups completed successfully")
    except Exception as e:
        print(f"DNS lookup error: {str(e)}")
        results['dns']['error'] = str(e)
        
        # Fallback for IP if DNS completely failed
        try:
            results['ip'] = socket.gethostbyname(domain)
            print(f"Got IP through socket fallback: {results['ip']}")
        except Exception as ip_e:
            print(f"Socket fallback failed: {str(ip_e)}")
    
    # WHOIS Lookup
    try:
        print(f"Attempting WHOIS lookup for {domain}")
        whois_info = whois.whois(domain)
        
        if whois_info:
            # Handle potential None values
            results['whois'] = {
                'registrar': str(whois_info.registrar) if whois_info.registrar else "Unknown",
                'creation_date': str(whois_info.creation_date) if whois_info.creation_date else "Unknown",
                'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else "Unknown",
                'updated_date': str(whois_info.updated_date) if whois_info.updated_date else "Unknown",
                'name_servers': whois_info.name_servers if whois_info.name_servers else [],
                'status': whois_info.status if whois_info.status else "Unknown",
                'dnssec': getattr(whois_info, 'dnssec', "Unknown")
            }
            
            # Check for domain age
            try:
                if isinstance(whois_info.creation_date, list) and whois_info.creation_date:
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                    
                if creation_date:
                    # Use datetime objects for comparison
                    if isinstance(creation_date, str):
                        try:
                            # Try different date formats
                            for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y.%m.%d', '%d.%m.%Y', '%d %b %Y']:
                                try:
                                    creation_date = datetime.strptime(creation_date, fmt)
                                    break
                                except:
                                    continue
                        except:
                            print("Could not parse creation date string")
                    
                    if isinstance(creation_date, datetime):
                        domain_age = (datetime.now() - creation_date).days
                        results['whois']['domain_age_days'] = domain_age
                        print(f"Domain age calculated: {domain_age} days")
            except Exception as age_e:
                print(f"Error calculating domain age: {str(age_e)}")
        else:
            results['whois']['error'] = "No WHOIS information available"
            
    except Exception as e:
        print(f"WHOIS lookup error: {str(e)}")
        results['whois']['error'] = str(e)
    
    return results

def perform_port_scan(domain):
    """Scan common ports on the target domain"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    results = {'open_ports': [], 'closed_ports': [], 'filtered_ports': []}
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            service = socket.getservbyport(port, 'tcp') if port < 1024 else f"port {port}"
            results['open_ports'].append({'port': port, 'service': service})
        else:
            # Can't reliably distinguish between closed and filtered
            results['closed_ports'].append({'port': port})
        sock.close()
    
    # Add summary
    results['summary'] = {
        'total_scanned': len(common_ports),
        'total_open': len(results['open_ports']),
        'total_closed_or_filtered': len(results['closed_ports'])
    }
    
    return results

def perform_ssl_scan(domain):
    """Analyze SSL/TLS certificate of the target domain"""
    results = {}
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate info
                results['subject'] = dict(x[0] for x in cert['subject'])
                results['issuer'] = dict(x[0] for x in cert['issuer'])
                results['version'] = cert['version']
                results['serial_number'] = cert['serialNumber']
                results['not_before'] = cert['notBefore']
                results['not_after'] = cert['notAfter']
                
                # Check if certificate is valid
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                results['is_valid'] = not_before <= now <= not_after
                results['days_until_expiry'] = (not_after - now).days
                
                # Check for common names
                san = cert.get('subjectAltName', [])
                results['alternative_names'] = [x[1] for x in san if x[0] == 'DNS']
                
                # Check certificate uses strong crypto
                results['signature_algorithm'] = cert.get('signatureAlgorithm')
    except Exception as e:
        results['error'] = str(e)
    
    return results

def perform_headers_scan(url, timeout=15):
    """Analyze HTTP headers for security headers"""
    results = {}
    
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = response.headers
        
        # Store all headers
        results['all_headers'] = dict(headers)
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-Frame-Options': False,
            'X-XSS-Protection': False,
            'X-Content-Type-Options': False,
            'Referrer-Policy': False,
            'Feature-Policy': False,
            'Permissions-Policy': False
        }
        
        for header in security_headers:
            security_headers[header] = header in headers
        
        results['security_headers'] = security_headers
        results['security_headers_present'] = sum(1 for h in security_headers.values() if h)
        results['security_headers_missing'] = sum(1 for h in security_headers.values() if not h)
        
        # Check for server information disclosure
        results['server_disclosure'] = 'Server' in headers
        if results['server_disclosure']:
            results['server_info'] = headers.get('Server')
            
        # Additional checks for a complete analysis
        results['cookies'] = [{
            'name': cookie.name,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('httponly'),
            'samesite': cookie.has_nonstandard_attr('samesite'),
            'expires': cookie.expires
        } for cookie in response.cookies]
    except Exception as e:
        results['error'] = str(e)
    
    return results

def calculate_risk_score(findings):
    """Calculate a risk score based on findings (0-100, higher is more risky)"""
    score = 0
    max_score = 0
    
    # Basic scan findings
    if 'basic' in findings:
        basic = findings['basic']
        # DNS security checks
        if 'dns' in basic:
            dns = basic['dns']
            # Check for SPF and DMARC
            if not dns.get('has_spf', False):
                score += 10
            if not dns.get('has_dmarc', False):
                score += 10
            max_score += 20
        
        # Domain age check
        if 'whois' in basic and 'domain_age_days' in basic['whois']:
            domain_age = basic['whois']['domain_age_days']
            if domain_age < 30:
                score += 20
            elif domain_age < 90:
                score += 10
            elif domain_age < 180:
                score += 5
            max_score += 20
    
    # Port scan findings
    if 'ports' in findings:
        ports = findings['ports']
        # Check for unnecessarily open ports
        risky_ports = [21, 23, 25, 3389]  # FTP, Telnet, SMTP, RDP
        for port_info in ports.get('open_ports', []):
            port = port_info['port']
            if port in risky_ports:
                score += 5
            max_score += 5
        max_score = max(max_score, 20)  # Cap port scan at 20 points
    
    # SSL scan findings
    if 'ssl' in findings:
        ssl = findings['ssl']
        # Check certificate validity
        if not ssl.get('is_valid', True):
            score += 30
        elif ssl.get('days_until_expiry', 100) < 15:
            score += 15
        elif ssl.get('days_until_expiry', 100) < 30:
            score += 5
        
        # Check for weak signature algorithms
        weak_algorithms = ['md5', 'sha1']
        if any(algo in str(ssl.get('signature_algorithm', '')).lower() for algo in weak_algorithms):
            score += 20
            
        max_score += 50
    
    # HTTP headers scan findings
    if 'headers' in findings:
        headers = findings['headers']
        # Missing security headers
        missing_headers = headers.get('security_headers_missing', 0)
        score += missing_headers * 5
        max_score += 40  # Maximum 8 headers * 5 points
        
        # Server information disclosure
        if headers.get('server_disclosure', False):
            score += 5
        max_score += 5
        
        # Cookie security
        cookie_issues = False
        for cookie in headers.get('cookies', []):
            if not cookie.get('secure', False) or not cookie.get('httponly', False) or not cookie.get('samesite', False):
                cookie_issues = True
                break
                
        if cookie_issues:
            score += 5  # Single score for any cookie issues
        max_score += 5
    
    # Normalize the score to 0-100
    if max_score > 0:
        return min(100, int((score / max_score) * 100))
    return 0

def generate_recommendations(findings):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    # Basic scan recommendations
    if 'basic' in findings:
        basic = findings['basic']
        # DNS security checks
        if 'dns' in basic:
            dns = basic['dns']
            if not dns.get('has_spf', False):
                recommendations.append({
                    'title': 'Implement SPF record',
                    'description': 'SPF (Sender Policy Framework) records help prevent email spoofing.',
                    'severity': 'medium',
                    'implementation': 'Add a TXT record with value "v=spf1 include:_spf.domain.com ~all"'
                })
            if not dns.get('has_dmarc', False):
                recommendations.append({
                    'title': 'Implement DMARC record',
                    'description': 'DMARC builds on SPF and DKIM to improve email security.',
                    'severity': 'medium',
                    'implementation': 'Add a TXT record at _dmarc.domain.com with value "v=DMARC1; p=none; rua=mailto:admin@domain.com"'
                })
        
        # Domain age check
        if 'whois' in basic and 'domain_age_days' in basic['whois']:
            domain_age = basic['whois']['domain_age_days']
            if domain_age < 30:
                recommendations.append({
                    'title': 'Recently registered domain',
                    'description': 'This domain was registered recently, which is sometimes associated with malicious activities.',
                    'severity': 'info',
                    'implementation': 'No action required, but be aware that new domains may face greater scrutiny.'
                })
    
    # Port scan recommendations
    if 'ports' in findings:
        ports = findings['ports']
        # Check for unnecessarily open ports
        risky_port_info = {
            21: {'name': 'FTP', 'alt': 'SFTP or FTPS'},
            23: {'name': 'Telnet', 'alt': 'SSH'},
            25: {'name': 'SMTP', 'alt': 'authenticated SMTP or API-based email delivery'},
            3389: {'name': 'RDP', 'alt': 'VPN with MFA'}
        }
        
        for port_info in ports.get('open_ports', []):
            port = port_info['port']
            if port in risky_port_info:
                info = risky_port_info[port]
                recommendations.append({
                    'title': f'Close or secure {info["name"]} port ({port})',
                    'description': f'This port is often targeted by attackers and may pose security risks if not properly secured.',
                    'severity': 'high',
                    'implementation': f'Consider using {info["alt"]} instead, or implement strict firewall rules.'
                })
    
    # SSL scan recommendations
    if 'ssl' in findings:
        ssl = findings['ssl']
        # Check certificate validity
        if not ssl.get('is_valid', True):
            recommendations.append({
                'title': 'Invalid SSL certificate',
                'description': 'Your SSL certificate is invalid. This can lead to browser warnings and reduced trust.',
                'severity': 'critical',
                'implementation': 'Renew your SSL certificate immediately through your hosting provider or a certificate authority.'
            })
        elif ssl.get('days_until_expiry', 100) < 15:
            recommendations.append({
                'title': 'SSL certificate expiring soon',
                'description': f'Your SSL certificate will expire in {ssl.get("days_until_expiry")} days.',
                'severity': 'high',
                'implementation': 'Renew your SSL certificate as soon as possible to avoid disruption.'
            })
        elif ssl.get('days_until_expiry', 100) < 30:
            recommendations.append({
                'title': 'SSL certificate expiring soon',
                'description': f'Your SSL certificate will expire in {ssl.get("days_until_expiry")} days.',
                'severity': 'medium',
                'implementation': 'Plan to renew your SSL certificate in the next few weeks.'
            })
        
        # Check for weak signature algorithms
        weak_algorithms = ['md5', 'sha1']
        if any(algo in str(ssl.get('signature_algorithm', '')).lower() for algo in weak_algorithms):
            recommendations.append({
                'title': 'Weak SSL signature algorithm',
                'description': 'Your SSL certificate uses a weak signature algorithm that is no longer considered secure.',
                'severity': 'high',
                'implementation': 'Reissue your certificate with a modern signature algorithm like SHA-256.'
            })
    
    # HTTP headers scan recommendations
    if 'headers' in findings:
        headers = findings['headers']
        # Missing security headers
        security_headers_info = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS and prevents downgrade attacks',
                'implementation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection attacks',
                'implementation': 'Add "Content-Security-Policy: default-src \'self\'" header and customize as needed'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'implementation': 'Add "X-Frame-Options: SAMEORIGIN" header'
            },
            'X-XSS-Protection': {
                'description': 'Provides basic XSS protection in older browsers',
                'implementation': 'Add "X-XSS-Protection: 1; mode=block" header'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME-type sniffing',
                'implementation': 'Add "X-Content-Type-Options: nosniff" header'
            },
            'Referrer-Policy': {
                'description': 'Controls information sent in the Referer header',
                'implementation': 'Add "Referrer-Policy: strict-origin-when-cross-origin" header'
            },
            'Feature-Policy': {
                'description': 'Restricts browser features',
                'implementation': 'Add "Feature-Policy" header with appropriate restrictions'
            },
            'Permissions-Policy': {
                'description': 'Modern version of Feature-Policy',
                'implementation': 'Add "Permissions-Policy" header with appropriate restrictions'
            }
        }
        
        security_headers = headers.get('security_headers', {})
        for header, present in security_headers.items():
            if not present and header in security_headers_info:
                info = security_headers_info[header]
                recommendations.append({
                    'title': f'Add {header} header',
                    'description': info['description'],
                    'severity': 'medium',
                    'implementation': info['implementation']
                })
        
        # Server information disclosure
        if headers.get('server_disclosure', False):
            recommendations.append({
                'title': 'Server information disclosure',
                'description': 'Your server reveals its software version, which can help attackers target known vulnerabilities.',
                'severity': 'low',
                'implementation': 'Configure your web server to remove or obfuscate the "Server" header.'
            })
        
        # Cookie security
        cookie_issues = False
        for cookie in headers.get('cookies', []):
            if not cookie.get('secure', False) or not cookie.get('httponly', False) or not cookie.get('samesite', False):
                cookie_issues = True
                break
                
        if cookie_issues:
            recommendations.append({
                'title': 'Improve cookie security',
                'description': 'One or more cookies lack proper security attributes like Secure, HttpOnly, or SameSite.',
                'severity': 'medium',
                'implementation': 'Set Secure, HttpOnly, and SameSite=Lax (or Strict) attributes on all cookies.'
            })
    
    return recommendations

@app.route('/schedule_scan', methods=['GET', 'POST'])
def schedule_scan():
    if 'user_id' not in session:
        flash('Please log in to schedule scans.', 'warning')
        return redirect(url_for('login'))
    
    form = NetworkScanForm()
    form.scan_type.choices += [('auto', 'Automatic (Select best scan type)')]
    
    # Add frequency field
    frequencies = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly')
    ]
    
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        frequency = request.form.get('frequency')
        
        if not target or not scan_type or not frequency:
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('schedule_scan'))
        
        # Calculate next scan time
        now = datetime.now()
        if frequency == 'daily':
            next_scan = now + timedelta(days=1)
        elif frequency == 'weekly':
            next_scan = now + timedelta(weeks=1)
        else:  # monthly
            next_scan = now + timedelta(days=30)
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO scheduled_scans (user_id, target, scan_type, frequency, next_scan)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], target, scan_type, frequency, next_scan))
        conn.commit()
        conn.close()
        
        flash('Scan scheduled successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('schedule_scan.html', form=form, frequencies=frequencies)

@app.route('/cancel_scheduled_scan/<int:scan_id>', methods=['POST'])
def cancel_scheduled_scan(scan_id):
    if 'user_id' not in session:
        flash('Please log in to manage scheduled scans.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE scheduled_scans SET active = 0 WHERE id = ? AND user_id = ?', 
                (scan_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Scheduled scan cancelled', 'info')
    return redirect(url_for('dashboard'))

@app.route('/generate_api_key', methods=['POST'])
def generate_api_key():
    if 'user_id' not in session:
        flash('Please log in to generate API keys.', 'warning')
        return redirect(url_for('login'))
    
    name = request.form.get('key_name')
    if not name:
        flash('Please provide a name for your API key', 'danger')
        return redirect(url_for('dashboard'))
    
    api_key = str(uuid.uuid4())
    
    conn = get_db_connection()
    conn.execute('INSERT INTO api_keys (user_id, api_key, name) VALUES (?, ?, ?)',
                (session['user_id'], api_key, name))
    conn.commit()
    conn.close()
    
    flash(f'API key generated: {api_key}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/revoke_api_key/<int:key_id>', methods=['POST'])
def revoke_api_key(key_id):
    if 'user_id' not in session:
        flash('Please log in to manage API keys.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', 
                (key_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('API key revoked', 'info')
    return redirect(url_for('dashboard'))

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    # Check API key authentication
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    conn = get_db_connection()
    key_info = conn.execute('SELECT * FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
    
    if not key_info:
        return jsonify({'error': 'Invalid API key'}), 401
    
    # Update last used timestamp
    conn.execute('UPDATE api_keys SET last_used = ? WHERE id = ?', 
                (datetime.now(), key_info['id']))
    conn.commit()
    
    # Get request data
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({'error': 'Target required'}), 400
    
    target = data['target']
    scan_type = data.get('scan_type', 'basic')
    
    # Validate scan type
    valid_scan_types = ['basic', 'ports', 'ssl', 'headers', 'full']
    if scan_type not in valid_scan_types:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    # Normalize target URL
    if not target.startswith(('http://', 'https://')) and not is_valid_ip(target):
        target = 'http://' + target
    
    # Perform the scan
    result = perform_network_scan(target, scan_type)
    
    # Save scan to history
    conn.execute('INSERT INTO scan_history (user_id, target, scan_type, results) VALUES (?, ?, ?, ?)',
                (key_info['user_id'], target, scan_type, json.dumps(result)))
    conn.commit()
    conn.close()
    
    return jsonify(result)

@app.route('/export_pdf/<int:scan_id>')
def export_pdf(scan_id):
    if 'user_id' not in session:
        flash('Please log in to export reports.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scan_history WHERE id = ? AND user_id = ?', 
                       (scan_id, session['user_id'])).fetchone()
    conn.close()
    
    if not scan:
        flash('Scan report not found or not authorized.', 'danger')
        return redirect(url_for('dashboard'))
    
    result = json.loads(scan['results'])
    
    # Create PDF using reportlab
    buffer = BytesIO()
    
    # Set up the document with letter size paper
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Add custom styles
    styles.add(ParagraphStyle(name='Title', 
                              parent=styles['Heading1'], 
                              fontSize=18, 
                              alignment=1))  # 1 is center alignment
    
    styles.add(ParagraphStyle(name='Subtitle', 
                              parent=styles['Heading2'], 
                              fontSize=14))
    
    styles.add(ParagraphStyle(name='Alert', 
                              parent=styles['Normal'], 
                              backColor=colors.lightgrey,
                              borderPadding=5))
    
    # Build the content
    content = []
    
    # Title
    content.append(Paragraph(f"Security Scan Report: {scan['target']}", styles['Title']))
    content.append(Spacer(1, 0.25*inch))
    
    # Metadata table
    metadata = [
        ['Target', scan['target']],
        ['Scan Type', scan['scan_type']],
        ['Scan Date', scan['created_at']],
        ['Report ID', str(scan['id'])]
    ]
    
    meta_table = Table(metadata, colWidths=[1.5*inch, 5*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 6)
    ]))
    content.append(meta_table)
    content.append(Spacer(1, 0.25*inch))
    
    # Risk score
    risk_score = result.get('risk_score', 0)
    risk_level = "Low" if risk_score < 40 else "Medium" if risk_score < 70 else "High"
    risk_color = colors.green if risk_score < 40 else colors.orange if risk_score < 70 else colors.red
    
    content.append(Paragraph(f"Risk Assessment: {risk_level} ({risk_score}%)", styles['Subtitle']))
    content.append(Spacer(1, 0.1*inch))
    
    # Executive summary
    summary_text = f"This report provides a detailed security assessment of {scan['target']} based on a {scan['scan_type']} scan."
    content.append(Paragraph(summary_text, styles['Normal']))
    content.append(Spacer(1, 0.1*inch))
    
    # Risk alert
    if risk_score > 70:
        alert = "This target has significant security vulnerabilities that should be addressed immediately."
    elif risk_score > 40:
        alert = "This target has some security concerns that should be addressed."
    else:
        alert = "This target has good security posture with few or minor issues identified."
    
    content.append(Paragraph(alert, styles['Alert']))
    content.append(Spacer(1, 0.25*inch))
    
    # Findings sections
    if 'findings' in result:
        content.append(Paragraph("Findings", styles['Subtitle']))
        
        # Basic findings
        if 'basic' in result['findings']:
            content.append(Paragraph("Basic Information", styles['Heading3']))
            
            basic = result['findings']['basic']
            
            # DNS info
            if 'dns' in basic and isinstance(basic['dns'], dict):
                content.append(Paragraph("DNS Records", styles['Heading4']))
                
                dns_data = []
                dns = basic['dns']
                
                # Add headers
                dns_data.append(["Record Type", "Value"])
                
                # A Records
                if 'a_records' in dns and dns['a_records']:
                    for record in dns['a_records']:
                        dns_data.append(["A Record", record])
                
                # SPF and DMARC
                if 'has_spf' in dns:
                    status = "Present" if dns['has_spf'] else "Not Present"
                    dns_data.append(["SPF Record", status])
                
                if 'has_dmarc' in dns:
                    status = "Present" if dns['has_dmarc'] else "Not Present"
                    dns_data.append(["DMARC Record", status])
                
                if len(dns_data) > 1:  # If we have data beyond headers
                    dns_table = Table(dns_data, colWidths=[1.5*inch, 5*inch])
                    dns_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('PADDING', (0, 0), (-1, -1), 6)
                    ]))
                    content.append(dns_table)
                    content.append(Spacer(1, 0.1*inch))
            
            # Add WHOIS information similarly
            # ... more code for other sections
        
        # Add other finding types (ports, ssl, headers)
        # ... more code for other sections
    
    # Recommendations
    if 'recommendations' in result and result['recommendations']:
        content.append(Paragraph("Security Recommendations", styles['Subtitle']))
        content.append(Spacer(1, 0.1*inch))
        
        rec_data = [["Issue", "Severity", "Recommendation"]]
        
        for rec in result['recommendations']:
            severity = rec.get('severity', 'medium')
            severity_color = colors.green
            if severity == 'high' or severity == 'critical':
                severity_color = colors.red
            elif severity == 'medium':
                severity_color = colors.orange
            
            rec_data.append([
                rec.get('title', 'Unknown Issue'),
                severity.capitalize(),
                f"{rec.get('description', '')}\n\nImplementation: {rec.get('implementation', '')}"
            ])
        
        if len(rec_data) > 1:  # If we have data beyond headers
            rec_table = Table(rec_data, colWidths=[2*inch, 1*inch, 3.5*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            content.append(rec_table)
    
    # Footer
    content.append(Spacer(1, 0.5*inch))
    footer = f"Report generated by PhishGuard Security Scanner on {datetime.now().strftime('%Y-%m-%d')}."
    content.append(Paragraph(footer, styles['Normal']))
    
    # Build the PDF
    doc.build(content)
    
    # Get the PDF from the buffer
    pdf_data = buffer.getvalue()
    buffer.close()
    
    # Return the PDF
    response = Response(pdf_data, mimetype='application/pdf')
    response.headers['Content-Disposition'] = f'attachment; filename=security_report_{scan_id}.pdf'
    return response

# Function to run scheduled scans
def run_scheduled_scans():
    print("Running scheduled scans...")
    conn = get_db_connection()
    now = datetime.now()
    
    # Get scans that are due to run
    due_scans = conn.execute('''
        SELECT * FROM scheduled_scans 
        WHERE active = 1 AND next_scan <= ?
    ''', (now,)).fetchall()
    
    for scan in due_scans:
        try:
            # Perform the scan
            target = scan['target']
            scan_type = scan['scan_type']
            
            if scan_type == 'auto':
                # Determine the best scan type based on the target
                if is_valid_ip(target):
                    scan_type = 'ports'  # For IPs, port scan is most relevant
                else:
                    scan_type = 'full'  # For domains, full scan
            
            # Normalize target URL if needed
            if not target.startswith(('http://', 'https://')) and not is_valid_ip(target):
                target = 'http://' + target
                
            result = perform_network_scan(target, scan_type)
            
            # Save scan to history
            conn.execute('''
                INSERT INTO scan_history (user_id, target, scan_type, results) 
                VALUES (?, ?, ?, ?)
            ''', (scan['user_id'], target, scan_type, json.dumps(result)))
            
            # Update last scan time and calculate next scan
            frequency = scan['frequency']
            if frequency == 'daily':
                next_scan = now + timedelta(days=1)
            elif frequency == 'weekly':
                next_scan = now + timedelta(weeks=1)
            else:  # monthly
                next_scan = now + timedelta(days=30)
                
            conn.execute('''
                UPDATE scheduled_scans 
                SET last_scan = ?, next_scan = ? 
                WHERE id = ?
            ''', (now, next_scan, scan['id']))
            
        except Exception as e:
            print(f"Error with scheduled scan {scan['id']}: {str(e)}")
    
    conn.commit()
    conn.close()

# Start the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=run_scheduled_scans,
    trigger=IntervalTrigger(minutes=15),
    id='scheduled_scan_job',
    name='Run scheduled security scans every 15 minutes',
    replace_existing=True
)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

# Enhanced result formatting
def format_result(url, prediction):
    """Create a more detailed and structured result object for display."""
    is_phishing = prediction.get('is_phishing', False)
    probability = prediction.get('probability', 0.5)
    features = prediction.get('features', {})
    
    message = get_message(prediction)
    phishing_type = determine_phishing_type(features, is_phishing)
    
    # Calculate risk level
    risk_level = "Low"
    risk_color = "success"
    if is_phishing:
        if probability > 0.9:
            risk_level = "Critical"
            risk_color = "danger"
        elif probability > 0.7:
            risk_level = "High"
            risk_color = "danger"
        elif probability > 0.5:
            risk_level = "Medium"
            risk_color = "warning"
    
    # Format suspicious indicators for display
    suspicious_indicators = []
    if features.get('has_ip', False):
        suspicious_indicators.append({"name": "IP Address in URL", "severity": "high"})
    if features.get('is_shortened', False):
        suspicious_indicators.append({"name": "URL Shortener Used", "severity": "high"})
    if features.get('has_at_symbol', False):
        suspicious_indicators.append({"name": "@ Symbol in URL", "severity": "high"})
    if features.get('has_suspicious_tld', False):
        suspicious_indicators.append({"name": "Suspicious TLD", "severity": "medium"})
    if features.get('domain_age_days', 365) < 30:
        suspicious_indicators.append({"name": "Recently Registered Domain", "severity": "medium"})
    if features.get('has_redirection', False):
        suspicious_indicators.append({"name": "URL Redirection", "severity": "medium"})
    if features.get('has_suspicious_keywords', False):
        suspicious_indicators.append({"name": "Suspicious Keywords", "severity": "medium"})
    
    # Generate recommendations based on findings
    recommendations = []
    if is_phishing:
        recommendations.append({
            "title": "Do not visit this site",
            "description": "This URL has been identified as potentially malicious.",
            "severity": "high"
        })
        recommendations.append({
            "title": "Check for legitimate alternatives",
            "description": "If you were expecting to visit a legitimate website, go directly to the official site by typing the address in your browser.",
            "severity": "medium"
        })
    else:
        recommendations.append({
            "title": "Exercise normal caution",
            "description": "While this URL appears legitimate, always be careful when entering sensitive information online.",
            "severity": "low"
        })
    
    result = {
        'url': url,
        'is_phishing': is_phishing,
        'probability': probability,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'message': message,
        'phishing_type': phishing_type,
        'suspicious_indicators': suspicious_indicators,
        'recommendations': recommendations,
        'features': features,
        'width_class': get_width_class(probability),
        'check_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'id': str(uuid.uuid4())
    }
    
    return result

if __name__ == '__main__':
    # Initialize the phishing detection model
    phishing_model = PhishingDetectionModel()
    
    # Force retrain the model with the new features
    print("Training a new model with updated features...")
    phishing_model.train(None)
    
    app.run(debug=True) 