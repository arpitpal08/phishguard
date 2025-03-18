from flask import Flask, render_template, request, jsonify, url_for, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
import os
from model import PhishingDetectionModel
import joblib
import json
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the phishing detection model
phishing_model = PhishingDetectionModel()

# Load or train the model
if not phishing_model.load_model():
    print("Training a new model...")
    phishing_model.train(None)

# URL submission form
class URLForm(FlaskForm):
    url = StringField('URL to Check', validators=[DataRequired(), URL()])
    submit = SubmitField('Check URL')

# Batch URL submission form
class BatchURLForm(FlaskForm):
    file = StringField('Upload a file with URLs (one per line)')
    submit = SubmitField('Check URLs')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = URLForm()
    batch_form = BatchURLForm()
    result = None
    
    if form.validate_on_submit():
        url = form.url.data
        
        # Check if URL is potentially dangerous before even analyzing
        if is_obviously_phishing(url):
            result = {
                'url': url,
                'is_phishing': True,
                'probability': 1.0,
                'message': 'This URL shows strong indicators of a phishing attempt.',
                'features': {'obvious_phishing': True}
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
                'features': prediction['features']
            }
        
    return render_template('index.html', form=form, batch_form=batch_form, result=result)

@app.route('/api/check', methods=['POST'])
def api_check():
    # Get URL from request
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL not provided'}), 400
    
    url = data['url']
    
    # Check for obviously malicious URLs
    if is_obviously_phishing(url):
        result = {
            'url': url,
            'is_phishing': True,
            'probability': 1.0,
            'message': 'This URL shows strong indicators of a phishing attempt.',
            'features': {'obvious_phishing': True}
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
            'features': prediction['features']
        }
    
    return jsonify(result)

@app.route('/batch', methods=['POST'])
def batch_check():
    # Check if file was uploaded
    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    # Check if file is empty
    if file.filename == '':
        flash('No file selected')
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
                # Get prediction
                prediction = phishing_model.predict(url)
                
                # Format result
                results.append({
                    'url': url,
                    'is_phishing': prediction['is_phishing'],
                    'probability': prediction['probability'],
                    'message': get_message(prediction)
                })
    
    return render_template('batch_results.html', results=results)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

def is_obviously_phishing(url):
    """Check for obviously malicious URLs before model prediction."""
    # Check for extremely suspicious patterns
    obvious_patterns = [
        r'paypal.*\.tk',
        r'bank.*\.info',
        r'verify.*\.xyz',
        r'secure.*login.*\.cc',
        r'\d+\.\d+\.\d+\.\d+/login',
        r'password.*reset.*\.(info|xyz|tk|ml)',
    ]
    
    return any(re.search(pattern, url.lower()) for pattern in obvious_patterns)

def get_message(prediction):
    """Get a human-readable message based on prediction results."""
    probability = prediction['probability']
    
    if prediction['is_phishing']:
        if probability > 0.9:
            return "High confidence this is a phishing URL. Do not visit this site!"
        elif probability > 0.7:
            return "This URL shows strong signs of being a phishing attempt. Proceed with caution."
        else:
            return "This URL has some characteristics of phishing sites. Be careful."
    else:
        if probability < 0.1:
            return "This URL appears to be legitimate with high confidence."
        elif probability < 0.3:
            return "This URL likely legitimate, but exercise normal caution."
        else:
            return "This URL may be legitimate but has some suspicious characteristics. Use caution."

if __name__ == '__main__':
    app.run(debug=True) 