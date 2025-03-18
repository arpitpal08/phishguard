# PhishGuard: AI-Powered Phishing Detection Tool

PhishGuard is an advanced web application that uses machine learning to detect phishing URLs. This project was developed as a final year project in cybersecurity.

## Features

- **AI-Powered Analysis**: Utilizes a Random Forest classifier to identify phishing URLs with high accuracy
- **Real-Time Detection**: Instantly analyzes URLs to determine if they're potential phishing attempts
- **Comprehensive Feature Analysis**: Examines multiple URL features including domain characteristics, suspicious patterns, and security indicators
- **Detailed Reports**: Provides clear risk assessments with probability scores and feature breakdowns
- **Batch Processing**: Supports checking multiple URLs at once via file upload
- **User-Friendly Interface**: Clean, responsive design with intuitive visualization of results
- **API Access**: JSON API endpoint for integration with other applications

## Tech Stack

- **Backend**: Python, Flask
- **Machine Learning**: scikit-learn, pandas, numpy, NLTK
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Data Processing**: Beautiful Soup, Requests

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Download required NLTK data:
   ```
   python download_nltk_data.py
   ```

5. Run the application:
   ```
   python app.py
   ```

6. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Single URL Check

1. Enter a URL in the input field on the homepage
2. Click "Check URL"
3. View the detailed analysis results

### Batch URL Check

1. Prepare a text file with one URL per line
2. Click "Choose File" in the batch check section
3. Upload your file and click "Check URLs"
4. View the analysis results for all URLs

### API Usage

Send a POST request to `/api/check` with a JSON payload:

```json
{
  "url": "https://example.com"
}
```

Response format:

```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "probability": 0.12,
  "message": "This URL appears to be legitimate with high confidence.",
  "features": {
    "url_length": 19,
    "dot_count": 1,
    "is_shortened": false,
    "has_suspicious": false,
    "has_ip": false,
    "domain_age": 1,
    "uses_https": true,
    "domain_length": 11,
    "special_char_count": 0,
    "subdomain_count": 0
  }
}
```

## How It Works

PhishGuard uses a machine learning approach to detect phishing URLs:

1. **Feature Extraction**: When a URL is submitted, multiple features are extracted including length, domain structure, and suspicious patterns.
2. **Preliminary Filtering**: Basic pattern matching is used to quickly identify obviously malicious URLs.
3. **Machine Learning Analysis**: A Random Forest classifier analyzes the extracted features to determine a phishing probability score.
4. **Risk Assessment**: A comprehensive risk assessment is generated based on the model's prediction and feature analysis.

The model is trained on a dataset of both legitimate and phishing URLs, and continually refined to improve accuracy.

## Future Enhancements

- Content-based analysis of website HTML/CSS for brand impersonation detection
- Browser extension for real-time protection while browsing
- Enhanced model training with larger and more diverse datasets
- User feedback loop to improve detection accuracy over time
- Integration with popular security tools and platforms

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Special thanks to our cybersecurity professors and mentors for their guidance
- The open-source community for providing excellent tools and libraries
- Security researchers who continually share phishing techniques and countermeasures 