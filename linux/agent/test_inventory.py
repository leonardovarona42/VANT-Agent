#!/usr/bin/env python3
import subprocess

cmd = "dpkg-query -W -f '${Package}\t${Version}\n' 2>&1 | head -3"
try:
    result = subprocess.check_output(cmd, shell=True, text=True)
    print("Result:", repr(result))
except Exception as e:
    print(f"Error: {e}")

# Also test basic -W
try:
    result2 = subprocess.check_output("dpkg-query -W 2>&1 | head -3", shell=True, text=True)
    print("\nBasic -W result:", repr(result2))
except Exception as e2:
    print(f"Basic error: {e2}")
