# PhishGuard - AI-Powered Phishing Detection

PhishGuard is an advanced web application that uses artificial intelligence to detect phishing websites and analyze network security. It provides comprehensive URL analysis, batch processing capabilities, and network security assessment tools.

## Features

- 🔍 **URL Analysis**: Check individual URLs for phishing indicators
- 📊 **Batch Processing**: Analyze multiple URLs simultaneously
- 🌐 **Network Security Analyzer**: Comprehensive security assessment of domains and IPs
- 🎓 **Educational Resources**: Learn about cybersecurity and phishing prevention
- 📈 **User Dashboard**: Track your scan history and analysis results

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/arpitpal08/phishguard.git
cd phishguard
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python
>>> from app import db
>>> db.create_all()
>>> exit()
```

5. Run the application:
```bash
python app.py
```

6. Open your browser and navigate to:
```
http://localhost:5000
```

## Features in Detail

### URL Analysis
- Real-time phishing detection
- Comprehensive security analysis
- Detailed threat indicators
- Risk score calculation

### Network Security Analyzer
- DNS record analysis
- Port scanning
- SSL certificate verification
- Security headers check
- Comprehensive security report

### Batch Processing
- Upload multiple URLs
- Bulk analysis
- Export results
- Detailed reporting

## Technology Stack

- **Backend**: Python, Flask
- **Database**: SQLite
- **Machine Learning**: Scikit-learn
- **Frontend**: HTML5, CSS3, JavaScript
- **Security**: SSL/TLS, CSRF Protection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

Arpit Pal - [LinkedIn](https://linkedin.com/in/yourusername)

Project Link: [https://github.com/arpitpal08/phishguard](https://github.com/arpitpal08/phishguard)

## Acknowledgments

- Thanks to all contributors who have helped this project grow
- Special thanks to the cybersecurity community for their valuable insights
- Built with ❤️ by Arpit Pal

## Security Features

- AI-based phishing detection
- Domain age verification
- SSL certificate validation
- Security header analysis
- Port scanning
- DNS record verification
- WHOIS information analysis
- Suspicious TLD detection
- Brand impersonation detection
- URL structure analysis
- Entropy-based analysis
- Homograph attack detection

## API Usage

### Authentication
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Response Format
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "probability": 0.12,
  "risk_score": 25,
  "findings": {
    "basic": {...},
    "ssl": {...},
    "headers": {...}
  }
}
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Access the web interface at `http://localhost:5000`

3. Register an account and log in

4. Start using the features:
   - URL scanning for phishing detection
   - Network security analysis
   - View the security dashboard
   - Generate reports

## API Usage

### Authentication
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Response Format
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "probability": 0.12,
  "risk_score": 25,
  "findings": {
    "basic": {...},
    "ssl": {...},
    "headers": {...}
  }
}
```

## Security Features

- AI-based phishing detection
- Domain age verification
- SSL certificate validation
- Security header analysis
- Port scanning
- DNS record verification
- WHOIS information analysis
- Suspicious TLD detection
- Brand impersonation detection
- URL structure analysis
- Entropy-based analysis
- Homograph attack detection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped with the project
- Special thanks to the open-source community for the tools and libraries used

## Verifying Your Installation

After following the setup instructions, you can verify that everything is properly installed by running the test script:

```bash
python test_setup.py
```

The script will check:
- Python version compatibility
- Required package installations
- Database setup and tables
- Presence of template files

If any issues are found, the script will provide detailed information about what needs to be fixed.

Example output:
```
PhishGuard Setup Verification
==============================

Checking Python version...
✅ Python version 3.9.5 is compatible

Checking dependencies...
✅ Flask 2.0.1 is installed
✅ Flask-SQLAlchemy 2.5.1 is installed
[...]

Checking database...
✅ Table 'user' exists
✅ Table 'scan_history' exists
✅ Table 'feedback' exists

Checking template files...
✅ Template base.html exists
✅ Template index.html exists
[...]

Verification Summary
==============================
✅ All checks passed! PhishGuard is properly set up.
You can now run the application using: python app.py
```

If you encounter any issues during the verification, please refer to the troubleshooting section below or open an issue on GitHub.