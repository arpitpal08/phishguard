# PhishGuard - Advanced Security Analysis Tool

PhishGuard is a comprehensive security analysis tool that combines phishing detection and network security scanning capabilities. It provides real-time analysis of URLs and network endpoints with AI-powered detection and detailed security assessments.

## Features

### Phishing Detection
- AI-powered phishing URL detection
- 30+ advanced detection features
- Real-time analysis
- Detailed threat assessment
- Historical tracking of scanned URLs

### Network Security Analysis
- Basic security scanning (DNS, WHOIS)
- Port scanning
- SSL/TLS certificate analysis
- HTTP security headers analysis
- Full security assessment

### Dashboard & Reporting
- Interactive security dashboard
- Risk score visualization
- Detailed scan reports
- PDF report generation
- Historical data tracking

### API Integration
- RESTful API access
- API key management
- Scheduled scanning
- Batch URL processing

## Technology Stack

- Python 3.x
- Flask (Web Framework)
- SQLite (Database)
- scikit-learn (Machine Learning)
- NLTK (Natural Language Processing)
- Chart.js (Data Visualization)
- Bootstrap 5 (Frontend)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python app.py
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