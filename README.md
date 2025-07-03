# penetration_testing
Penetration Testing Toolkit A Python GUI tool for ethical hacking. Includes a port scanner and SSH brute forcer with real-time logs and multithreading.
✅ STEP 1: Install Python
Download and install Python 3.9 or above from https://python.org

During install, check the box that says “Add Python to PATH”

✅ STEP 2: Create a Project Folder
Create a folder for your project:

plaintext
Copy
Edit
PenTestToolkit/
└── penetration_toolkit.py
Paste your full code into penetration_toolkit.py

✅ STEP 3: Install Required Libraries
Open Command Prompt or Terminal, and run:

bash
Copy
Edit
pip install paramiko
(Only paramiko is external; others like tkinter, socket, threading are built-in)

✅ STEP 4: Run the Toolkit
Navigate to your folder in terminal:

bash
Copy
Edit
cd path\to\PenTestToolkit
python penetration_toolkit.py
(Example: cd E:\PenTestToolkit)

✅ STEP 5: Use the Toolkit
Port Scanner Tab:

Enter a valid IP (e.g., 127.0.0.1)

Enter start port (e.g., 20) and end port (e.g., 100)

Click Start Scan

SSH Brute Forcer Tab:

Enter IP and port (default: 22)

Enter comma-separated usernames and passwords

Click Start Brute Force

⚠️ Note: Use this tool only on systems you own or are authorized to test. Unauthorized use is illegal.
