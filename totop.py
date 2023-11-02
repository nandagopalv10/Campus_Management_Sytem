import pyotp
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Simulating user data (for demonstration purposes)
user_secret = pyotp.random_base32()
user_username = "me"
user_password = "me"
user_email = "user@mail.com"

def generate_totp_token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()
# Simulating sending the email (for demonstration purposes)
def send_email(subject, body, to_email):
    server = smtplib.SMTP("localhost", 8000)  # Replace with your SMTP server's address and port
    # No need to start TLS as the server doesn't support it

    msg = MIMEMultipart()
    msg['From'] = user_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    server.sendmail(user_email, to_email, msg.as_string())

    server.quit()
def main():
    print("Two-Factor Authentication Demo")

    input_username = input("Enter your username: ")
    input_password = input("Enter your password: ")

    if input_username == user_username and input_password == user_password:
        totp_token = generate_totp_token(user_secret)
        print("Your TOTP token:", totp_token)
        
        send_email("Your Two-Factor Authentication Code", f"Your TOTP token: {totp_token}", user_email)

        input_totp_token = input("Enter the TOTP token from your authenticator app: ")
        input_email_code = input("Enter the code sent to your email: ")

        if totp_token == input_totp_token and input_email_code == str(totp_token):
            print("Authentication successful! You are now logged in.")
        else:
            print("Authentication failed. Invalid TOTP token or email code.")
    else:
        print("Authentication failed. Invalid username or password.")

if __name__ == "__main__":
    main()
