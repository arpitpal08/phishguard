import sys
import pkg_resources
import sqlite3
import os

def check_python_version():
    print("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ Error: Python 3.7 or higher is required")
        return False
    print(f"✅ Python version {sys.version.split()[0]} is compatible")
    return True

def check_dependencies():
    print("\nChecking dependencies...")
    required = {
        "Flask": "2.0.1",
        "Flask-SQLAlchemy": "2.5.1",
        "Flask-Login": "0.5.0",
        "Flask-WTF": "0.15.1",
        "Werkzeug": "2.0.1",
        "requests": "2.26.0",
        "beautifulsoup4": "4.9.3",
        "scikit-learn": "0.24.2",
        "numpy": "1.21.2",
        "pandas": "1.3.3"
    }
    
    all_installed = True
    for package, version in required.items():
        try:
            pkg_resources.require(f"{package}=={version}")
            print(f"✅ {package} {version} is installed")
        except pkg_resources.VersionConflict as e:
            print(f"⚠️ {package} version conflict: {e}")
            all_installed = False
        except pkg_resources.DistributionNotFound:
            print(f"❌ {package} is not installed")
            all_installed = False
    return all_installed

def check_database():
    print("\nChecking database...")
    if not os.path.exists('phishguard.db'):
        print("❌ Database file not found")
        return False
    
    try:
        conn = sqlite3.connect('phishguard.db')
        cursor = conn.cursor()
        
        # Check required tables
        tables = ['user', 'scan_history', 'feedback']
        for table in tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                print(f"❌ Table '{table}' not found in database")
                return False
            print(f"✅ Table '{table}' exists")
        
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False

def check_templates():
    print("\nChecking template files...")
    required_templates = [
        'base.html',
        'index.html',
        'login.html',
        'register.html',
        'dashboard.html',
        'network_analyzer.html'
    ]
    
    all_exist = True
    for template in required_templates:
        path = os.path.join('templates', template)
        if os.path.exists(path):
            print(f"✅ Template {template} exists")
        else:
            print(f"❌ Template {template} not found")
            all_exist = False
    return all_exist

def main():
    print("PhishGuard Setup Verification\n" + "="*30 + "\n")
    
    checks = [
        check_python_version(),
        check_dependencies(),
        check_database(),
        check_templates()
    ]
    
    print("\nVerification Summary")
    print("="*30)
    if all(checks):
        print("\n✅ All checks passed! PhishGuard is properly set up.")
        print("You can now run the application using: python app.py")
    else:
        print("\n❌ Some checks failed. Please fix the issues above before running the application.")
        print("Refer to the README.md file for setup instructions.")

if __name__ == "__main__":
    main() 