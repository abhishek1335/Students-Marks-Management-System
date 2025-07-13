import smtplib

try:
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login("darkplayer1335@gmail.com", "mwzh qyhp nnev tobj")
    print("SMTP connection successful!")
    server.quit()
except Exception as e:
    print("Error:", e)
