from os import system
input("Are you sure you have configured the settings. py file? Once confirmed, press Enter")
print("Start environment configuration...")
system("pip3 install -r requirements.txt")
print("Starting server. py ...")
system("nohup python3 server.py &")
print("Start execution completed!")
print("You can use ps aux | grep server. py to check if the script runs successfully")
