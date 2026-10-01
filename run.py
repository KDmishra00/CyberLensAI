#!/usr/bin/env python3
"""Start CyberLensAI server"""
import subprocess, sys, os, time, signal

# Kill any existing process on port 5050
os.system("lsof -ti:5050 | xargs kill 2>/dev/null")
time.sleep(1)

# Start the server
proc = subprocess.Popen(
    [sys.executable, "-c", "from app import app; app.run(debug=False, host='127.0.0.1', port=5050)"],
    stdout=open("/tmp/cyberlens.log", "w"),
    stderr=subprocess.STDOUT,
    start_new_session=True,
)

# Write PID for easy cleanup
with open("/tmp/cyberlens.pid", "w") as f:
    f.write(str(proc.pid))

print(f"Server started (PID: {proc.pid})")
print("URL: http://127.0.0.1:5050")
print("Login: admin / admin123")
