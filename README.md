# Turkish Travel Advice Website Honeypot

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey)
![SQLite](https://img.shields.io/badge/SQLite-3.x-green)
![Twilio](https://img.shields.io/badge/Twilio-API-red)
![License](https://img.shields.io/badge/License-MIT-green)

A sophisticated honeypot web application designed for educational purposes in cybersecurity, simulating a Turkish travel advice website with intentional vulnerabilities for security testing and analysis.

## 📋 Overview

This project implements a Flask-based honeypot system that mimics a Turkish travel advice website. It's designed for the CS 437 Cybersecurity course at Sabanci University, featuring various security mechanisms and intentional vulnerabilities for educational purposes.

## 🎯 Project Goals

- Demonstrate real-world web application vulnerabilities
- Implement and test various security mechanisms
- Provide hands-on experience with security testing
- Monitor and analyze potential security breaches
- Educate about common web application security issues

## 📊 Key Features

### Content Management
- Dynamic RSS feed integration for travel advice
- Real-time content updates
- News article management system
- Interactive comment system

### Security Systems
- Multi-level authentication:
  - Member login with basic CAPTCHA
  - Admin login with MFA
  - SMS-based password reset
- Comprehensive logging system
- Rate limiting implementation
- Security breach monitoring

### Testing Tools
- CAPTCHA breaker demonstration
- Brute force attack simulation
- Security testing scripts
- Vulnerability assessment tools

## 🛠️ Technologies Used

- Python 3.x
- Flask web framework
- SQLite database
- Twilio API for SMS
- Flask-Mail for email
- CAPTCHA implementation
- Feedparser for RSS
- Security logging system

## 📈 Project Structure

1. **Web Application**
   - Main application server
   - Route handlers
   - Template rendering
   - Static file serving

2. **Authentication System**
   - Member authentication
   - Admin authentication
   - Password reset mechanisms
   - CAPTCHA implementation

3. **Database Management**
   - User data storage
   - Admin management
   - Comment system
   - Security logs

4. **Security Testing**
   - CAPTCHA breaker script
   - Brute force attack script
   - Vulnerability assessment tools

## 💻 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/turkish-travel-honeypot.git
cd turkish-travel-honeypot
```

2. Install required packages:
```bash
pip install flask flask-mail sqlite3 captcha twilio feedparser
```

3. Configure the application:
   - Set up SMTP settings
   - Configure Twilio API credentials
   - Update other configuration parameters

4. Initialize the database:
```bash
python database_init.py
```

5. Start the application:
```bash
python app.py
```

Access the system at `http://localhost:5000`

## 🔍 Security Testing

### CAPTCHA Breaker
```bash
python breakcap.py
```
Demonstrates how the application's simple CAPTCHA can be bypassed.

### Brute Force Attack
```bash
python brute.py
```
Tests the vulnerability of the password reset feature through brute force attempts.

## ⚠️ Security Considerations

- This is an educational project
- Contains intentional vulnerabilities
- For testing and learning purposes only
- Not suitable for production use
- Use in controlled environment

## 👤 Author

Mert Ali Celik

## 🙏 Acknowledgments

- Sabanci University CS 437 Course
- Open-source security community
- Contributors and testers
- Educational resources
