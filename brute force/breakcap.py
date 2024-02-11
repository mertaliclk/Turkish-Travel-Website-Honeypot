import requests
from bs4 import BeautifulSoup
import re
session = requests.Session()
# Function to calculate the CAPTCHA solution
def get_captcha_solution(captcha_question):
    # Find the mathematical operation within the question
    match = re.search(r'(\d+)\s*([+\-*])\s*(\d+)', captcha_question)
    if match:
        num1, operation, num2 = match.groups()
        num1, num2 = int(num1), int(num2)
        if operation == '+':
            return num1 + num2
        elif operation == '-':
            return num1 - num2
        elif operation == '*':
            return num1 * num2
    return None

def login_with_captcha_solution(login_url, email, password):
    # First, get the login page to obtain cookies and CAPTCHA
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract the CAPTCHA question
    captcha_label = soup.find('label', string=re.compile(r'CAPTCHA:'))
    if captcha_label:
        captcha_question = captcha_label.text.split(':')[1].strip()
        captcha_solution = get_captcha_solution(captcha_question)
        
        data = {
            'email': email,
            'password': password,
            'captcha': str(captcha_solution)
        }
        print(f"Found captcha: {captcha_question}")
        print(f"Answered: {captcha_solution}")
        # Send the POST request with cookies and data
        response = session.post(login_url, data=data)
        return response
    else:
        print("CAPTCHA not found.")
        return None

# Example usage
login_url = "http://127.0.0.1:5000/login"
email = "asd@mail.com"
password = "123"

response = login_with_captcha_solution(login_url, email, password)
if response:
    # Check if login was successful
    if "Logout" in response.text:
    	print("Login successful!")
    else:
        print("Login failed. Response:", response.text)
else:
    print("Failed to make login request.")
