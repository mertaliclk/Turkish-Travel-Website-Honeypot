# Turkish Travel Advice Website Honeypot
This project is a Flask-based web application designed as a honeypot for a Turkish travel advice/news website. It features a decoy system displaying current news, a member and admin login system with distinct security mechanisms, and a monitoring system to track user interactions and potential security breaches. The application is designed to replicate certain vulnerabilities for educational and security testing purposes for Sabanci University CS 437 Cybersecurity course.

Features
Dynamic Content Delivery: Utilizes RSS feeds to display up-to-date travel advice and restrictions, providing dynamic content to engage users and deter honeypot detection.

User Authentication System: Includes a member login with a simple CAPTCHA mechanism and a vulnerable password reset feature lacking rate limiting, susceptible to brute force attacks.

Admin Authentication System: Features an admin login with multi-factor authentication (MFA), a more secure CAPTCHA, and a password reset mechanism via SMS with proper rate limiting.

Security Logging: Implements a logging system to monitor login attempts, password reset requests, and other significant actions, distinguishing between normal and suspicious activities.

Interactive Comment System: Allows registered members to post comments on news articles and admins to manage these comments.

### Prerequisites & Setup

    pip install flask flask-mail sqlite3 captcha twilio feedparser

Fill in the configuration details in the application for SMTP settings, Twilio API credentials, and any other required information in placeholders.

### Database Initialization
The database script creates three tables: users, admins, and comments, and populates them with sample data. Users and admins are added with hashed passwords for security.

    python database_init.py

### Usage
Start the application:

    python app.py
Access it via http://localhost:5000 in a web browser to interact with the honeypot's features.

### Security Testing Scripts
#### CAPTCHA Breaker
The breakcap.py script demonstrates how the application's simple CAPTCHA can be bypassed. It programmatically solves the CAPTCHA on the login page and attempts to log in with a given email and password. 

#### Brute Force Attack
The brute.py script is designed to test the vulnerability of the password reset feature. It attempts to guess the reset code through brute force, exploiting the lack of rate limiting.
