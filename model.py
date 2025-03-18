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
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Feature 1: Length of URL
        features['url_length'] = len(url)
        
        # Feature 2: Number of dots in domain
        features['dot_count'] = url.count('.')
        
        # Feature 3: Use of URL shortening service
        short_services = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'tiny.cc', 'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at']
        features['is_shortened'] = any(service in domain for service in short_services)
        
        # Feature 4: Presence of suspicious words
        suspicious_words = ['secure', 'account', 'login', 'verify', 'update', 'confirm', 'banking', 'password', 
                           'access', 'authenticate', 'wallet', 'validation', 'unauthorized', 'security', 'paypal',
                           'alert', 'limited', 'suspended', 'unusual', 'billing', 'recovery', 'signin', 'submit',
                           'reset', 'authorize', 'expire', 'official', 'urgent', 'important', 'required',
                           'webscr', 'service', 'verification', 'identity', 'authenticate', 'ebay', 'microsoft',
                           'apple', 'amazon', 'facebook', 'google', 'netflix', 'payment', 'support', 'notification']
        features['has_suspicious'] = any(word in url.lower() for word in suspicious_words)
        
        # Feature 5: Presence of IP address in URL
        features['has_ip'] = bool(re.match(
            r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/?.*$', url))
        
        # Feature 6: Domain age approximation
        known_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com', 
            'youtube.com', 'netflix.com', 'twitter.com', 'instagram.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'linkedin.com', 'ebay.com',
            'yahoo.com', 'twitch.tv', 'spotify.com', 'snapchat.com', 'tiktok.com', 'zoom.us',
            'pinterest.com', 'dropbox.com', 'quora.com', 'yelp.com', 'walmart.com', 'etsy.com',
            'salesforce.com', 'adobe.com', 'shopify.com', 'tumblr.com', 'vimeo.com',
            'wordpress.com', 'medium.com', 'nytimes.com', 'cnn.com', 'bbc.com', 'forbes.com',
            'github.io', 'gitlab.com', 'paypal.com', 'outlook.com', 'office.com', 'live.com',
            'netflix.com', 'cloudflare.com', 'oracle.com', 'ibm.com', 'intel.com', 'amd.com'
        ]
        
        # TLDs highly associated with phishing
        suspicious_tlds = ['.tk', '.xyz', '.top', '.club', '.online', '.site', '.cc', '.cf', '.ga', '.gq', '.ml', '.bid', '.pw',
                           '.rest', '.cam', '.uno', '.icu', '.vip', '.fit', '.ren', '.kim', '.party', '.review', '.men', '.work']
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Check if it's a known legitimate domain (expanded list)
        if any(domain.endswith(d) or domain == d for d in known_domains):
            features['domain_age'] = 10  # Higher value for known sites
        else:
            features['domain_age'] = 1  # Lower for unknown sites
        
        # Feature 7: Use of HTTPS
        features['uses_https'] = url.startswith('https')
        
        # Feature 8: Length of domain name
        features['domain_length'] = len(domain)
        
        # Feature 9: Number of special characters
        features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        
        # Feature 10: Number of subdomains
        features['subdomain_count'] = len(domain.split('.')) - 1
        
        # Feature 11: Domain popularity (dummy for known sites)
        features['is_popular_domain'] = any(domain.endswith(d) or domain == d for d in known_domains)
        
        # Feature 12: Path length
        features['path_length'] = len(path)
        
        # Feature 13: Query parameters count
        features['query_param_count'] = len(query.split('&')) if query else 0
        
        # Feature 14: URL contains brand name but isn't the brand's domain
        brand_names = ['facebook', 'google', 'apple', 'amazon', 'microsoft', 'netflix', 'paypal', 'ebay', 
                      'instagram', 'twitter', 'linkedin', 'spotify', 'adobe', 'yahoo', 'chase', 'wellsfargo',
                      'bankofamerica', 'citibank', 'amex', 'americanexpress', 'mastercard', 'visa',
                      'whatsapp', 'telegram', 'gmail', 'outlook', 'hotmail', 'office365', 'onedrive']
        features['brand_in_subdomain'] = any(brand in domain and not domain.endswith(f"{brand}.com") for brand in brand_names)
        
        # Feature 15: Numbers in domain
        features['numbers_in_domain'] = len(re.findall(r'\d', domain))
        
        # Feature 16: URL redirects in path or query
        features['has_redirection'] = 'redirect' in url.lower() or 'url=' in url.lower() or 'link=' in url.lower()
        
        # Feature 17: Uses data URI scheme
        features['uses_data_uri'] = url.startswith('data:')
        
        # Feature 18: Presence of @ symbol in URL
        features['has_at_symbol'] = '@' in url
        
        # Feature 19: Double slashes in path (not counting protocol)
        path_slashes = path.count('/')
        features['excessive_slashes'] = path_slashes > 3  # More than normal for most URLs
        
        # Feature 20: Domain is all numeric
        domain_part = domain.split('.')[0]
        features['domain_is_numeric'] = domain_part.isdigit()
        
        # Feature 21: Domain uses hyphens extensively
        features['excessive_hyphens'] = domain.count('-') > 2
        
        # Feature 22: Suspicious query parameters
        suspicious_params = ['login', 'user', 'password', 'passwd', 'secret', 'account', 'ssn', 'creditcard']
        features['suspicious_params'] = any(param in query for param in suspicious_params)
        
        # Feature 23: Domain entropy (randomness score)
        domain_text = domain.split('.')[0]
        if domain_text:
            # Simplified entropy calculation based on character distribution
            char_counts = {}
            for char in domain_text:
                char_counts[char] = char_counts.get(char, 0) + 1
            entropy = 0
            for count in char_counts.values():
                probability = count / len(domain_text)
                entropy -= probability * np.log2(probability)
            features['domain_entropy'] = entropy
        else:
            features['domain_entropy'] = 0
            
        # Feature 24: Path includes file extensions that are often malicious
        suspicious_extensions = ['.exe', '.zip', '.rar', '.js', '.php', '.cgi', '.scr', '.bat']
        features['suspicious_extension'] = any(path.endswith(ext) for ext in suspicious_extensions)
        
        # Feature 25: Domain length to domain label count ratio
        label_count = len(domain.split('.'))
        features['domain_label_ratio'] = features['domain_length'] / label_count if label_count > 0 else 0
        
        # Feature 26: Keywords in path that suggest deception
        deceptive_path_keywords = ['admin', 'login', 'signin', 'verify', 'securepage', 'secure', 'update', 'confirm']
        features['deceptive_path'] = any(keyword in path for keyword in deceptive_path_keywords)
        
        # Feature 27: Unusual port usage in URL
        has_port = bool(re.search(r':\d+', domain))
        features['unusual_port'] = has_port and not (":80" in domain or ":443" in domain)
        
        # Feature 28: Hostname length
        hostname = domain.split(".")[0] if "." in domain else domain
        features['hostname_length'] = len(hostname)
        
        # Feature 29: Presence of Unicode characters (IDN homograph attack)
        features['has_unicode'] = any(ord(char) > 127 for char in url)
        
        # Feature 30: Multiple TLDs in path (e.g., phishing.com/legitimate.com)
        features['multiple_tlds_in_path'] = len(re.findall(r'\.(com|net|org|edu|gov|io|co|info)', path)) > 0
        
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
            # Legitimate URLs - popular sites
            'https://google.com',
            'https://facebook.com',
            'https://amazon.com',
            'https://apple.com',
            'https://microsoft.com',
            'https://youtube.com',
            'https://netflix.com',
            'https://twitter.com',
            'https://instagram.com',
            'https://linkedin.com',
            'https://github.com',
            'https://stackoverflow.com',
            'https://wikipedia.org',
            'https://reddit.com',
            'https://cnn.com',
            'https://nytimes.com',
            'https://bbc.com',
            # Legitimate URLs with "suspicious" words but legitimate domains
            'https://accounts.google.com/login',
            'https://secure.amazon.com/account',
            'https://facebook.com/login.php',
            'https://github.com/login',
            'https://netflix.com/login',
            'https://paypal.com/signin',
            'https://secure.etsy.com',
            # Phishing URLs - typosquatting
            'https://g00gle.com',
            'https://faceb00k.com',
            'https://amaz0n-account.com',
            'https://appleid-verify.com',
            'https://mlcrosoft.com',
            'https://netfl1x.com/login',
            'https://twltter.com',
            'https://1nstagram.com',
            # Phishing URLs - suspicious structures
            'https://secure-bank-login.com',
            'https://verify-account-paypal.com',
            'https://login-secure-bank.com',
            'http://193.28.72.11/login',
            'http://bit.ly/suspicious-login',
            'http://update-your-account.com',
            'http://banking-secure-login.com',
            'http://verify-payment-required.com',
            'http://secure-login-required.info',
            'http://account-verify-today.net',
            # Phishing URLs - brand in subdomain
            'http://paypal.secure-login.com',
            'http://apple.id-verify.net',
            'http://amazon.account-update.info',
            'http://netflix.billing-update.co',
            'http://microsoft.password-reset.org',
            # Phishing URLs - suspicious TLDs
            'http://login-verify.tk',
            'http://account-service.xyz',
            'http://secure-payment.ml',
            'http://verification-required.gq',
            'http://bank-secure.cf'
        ]
        
        # Count URLs for legitimate and phishing categories
        legitimate_count = 24  # First 24 URLs are legitimate
        phishing_count = len(urls) - legitimate_count  # Remaining are phishing
        
        # Labels: 0 for legitimate, 1 for phishing
        labels = [0] * legitimate_count + [1] * phishing_count
        
        # Ensure both arrays have the same length
        print(f"URLs: {len(urls)}, Labels: {len(labels)}")
        assert len(urls) == len(labels), "URLs and labels must have the same length"
        
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
        probability = self.model.predict_proba(features_df)[0][1]
        
        # Use a higher threshold (0.6) to reduce false positives
        # Default is 0.5, increasing it means we need more confidence to label as phishing
        prediction = 1 if probability > 0.6 else 0
        
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