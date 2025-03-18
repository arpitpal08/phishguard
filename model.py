import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import requests
from bs4 import BeautifulSoup

# Set of stopwords
stop_words = set(stopwords.words('english'))

class PhishingDetectionModel:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.model_path = 'phishing_model.pkl'
        self.vectorizer_path = 'vectorizer.pkl'
        
    def extract_features(self, url):
        """Extract features from a URL for phishing detection."""
        features = {}
        
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Feature 1: Length of URL
        features['url_length'] = len(url)
        
        # Feature 2: Number of dots in domain
        features['dot_count'] = url.count('.')
        
        # Feature 3: Use of URL shortening service
        short_services = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd']
        features['is_shortened'] = any(service in url for service in short_services)
        
        # Feature 4: Presence of suspicious words
        suspicious_words = ['secure', 'account', 'login', 'verify', 'update', 'confirm', 'banking']
        features['has_suspicious'] = any(word in url.lower() for word in suspicious_words)
        
        # Feature 5: Presence of IP address in URL
        features['has_ip'] = bool(re.match(
            r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/?.*$', url))
        
        # Feature 6: Domain age (dummy implementation)
        features['domain_age'] = 1  # Would normally do a WHOIS lookup
        
        # Feature 7: Use of HTTPS
        features['uses_https'] = url.startswith('https')
        
        # Feature 8: Length of domain name
        domain = parsed_url.netloc
        features['domain_length'] = len(domain)
        
        # Feature 9: Number of special characters
        features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        
        # Feature 10: Number of subdomains
        features['subdomain_count'] = len(domain.split('.')) - 1
        
        return features
    
    def get_webpage_content(self, url):
        """Get webpage content for additional text analysis."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract text from the webpage
                text = soup.get_text(separator=' ', strip=True)
                
                # Remove stopwords
                tokens = word_tokenize(text.lower())
                filtered_tokens = [word for word in tokens if word.isalnum() and word not in stop_words]
                return ' '.join(filtered_tokens)
            return ""
        except Exception as e:
            print(f"Error fetching content: {e}")
            return ""
    
    def train(self, data_path):
        """Train the phishing detection model."""
        # Load data (this would be your labeled dataset)
        # For demonstration, I'll create a synthetic dataset
        urls = [
            'https://google.com',
            'https://facebook.com',
            'https://amazon.com',
            'https://apple.com',
            'https://microsoft.com',
            'https://rnicrosoft.com',  # Typosquatting
            'https://g00gle.com',      # Typosquatting
            'https://faceb00k.com',    # Typosquatting
            'https://amaz0n.com',      # Typosquatting
            'https://secure-bank-login.com',
            'https://verify-account-paypal.com',
            'https://login-secure-bank.com',
            'http://193.28.72.11/login',
            'http://bit.ly/suspicious',
            'http://update-your-account.com',
            'http://banking-secure-login.com',
            'http://verify-payment-required.com',
            'http://secure-login-required.info',
            'http://account-verify-today.net'
        ]
        
        # Labels: 0 for legitimate, 1 for phishing
        labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        
        # Create DataFrame
        df = pd.DataFrame({
            'url': urls,
            'label': labels
        })
        
        # Extract features
        feature_list = []
        for url in df['url']:
            features = self.extract_features(url)
            feature_list.append(features)
        
        features_df = pd.DataFrame(feature_list)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(features_df, df['label'], test_size=0.2, random_state=42)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model Accuracy: {accuracy * 100:.2f}%")
        print(classification_report(y_test, y_pred))
        
        # Save model
        joblib.dump(self.model, self.model_path)
        print(f"Model saved to {self.model_path}")
        
    def load_model(self):
        """Load a trained model if it exists."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            return True
        return False
            
    def predict(self, url):
        """Predict if a URL is phishing or legitimate."""
        if self.model is None and not self.load_model():
            print("Model not trained. Training now...")
            self.train(None)
            
        # Extract features
        features = self.extract_features(url)
        features_df = pd.DataFrame([features])
        
        # Make prediction
        prediction = self.model.predict(features_df)[0]
        probability = self.model.predict_proba(features_df)[0][1]
        
        return {
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'features': features
        }

if __name__ == "__main__":
    # Test the model
    model = PhishingDetectionModel()
    model.train(None)  # Train with synthetic data
    
    test_urls = [
        'https://google.com',
        'https://verify-account-suspicious.com',
        'https://netflix-account-verify.net'
    ]
    
    for url in test_urls:
        result = model.predict(url)
        print(f"URL: {url}")
        print(f"Is Phishing: {result['is_phishing']}")
        print(f"Probability: {result['probability']:.2f}")
        print("---") 