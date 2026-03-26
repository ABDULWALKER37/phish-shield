"""
Helper script to verify VirusTotal API key presence and do a minimal test request.

Usage:
  # from project root
  python scripts/check_vt_key.py

This will:
 - load environment variables from a `.env` file if present
 - check that VT_API_KEY is set
 - optionally attempt a lightweight VirusTotal request to confirm the key is accepted

Notes:
 - This script will not print your API key.
 - If you don't want the test request, run the script without network access or uninstall `virustotal-python`.
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

key = os.environ.get("VT_API_KEY")
if not key:
    print("VT_API_KEY is NOT set.\n")
    print("Fixes:\n - Copy `.env.example` to `.env` and add your key\n - Or set the key in PowerShell: $env:VT_API_KEY = 'your_key'\n - Or set permanently: setx VT_API_KEY \"your_key\"")
    sys.exit(2)

print("VT_API_KEY is present in the environment (value hidden for security).")

# Try a small VirusTotal request to verify the key (network required)
try:
    from virustotal_python import Virustotal
except Exception as e:
    print("Unable to import `virustotal-python`. Install requirements: pip install -r requirements.txt")
    print("Import error:", e)
    sys.exit(3)

print("Attempting a small VirusTotal request to check the key...")
try:
    with Virustotal(key) as vtotal:
        # Query a public IP (8.8.8.8) as a lightweight test. If the key is invalid or rate-limited
        # VirusTotal will return an error message which we catch and summarize.
        resp = vtotal.request("ip_addresses/8.8.8.8")
        # resp may be a requests.Response-like object
        try:
            data = resp.json()
        except Exception:
            print("Unable to parse JSON response from VirusTotal; raw response received.")
            print("HTTP status:", getattr(resp, 'status_code', 'unknown'))
            sys.exit(0)

        # Check for error in response
        if isinstance(data, dict) and data.get("error"):
            err = data.get("error")
            # Avoid printing the key; print the message only
            print("VirusTotal returned an error:", err.get("message") if isinstance(err, dict) else str(err))
            sys.exit(4)

        # If we get here, VirusTotal returned some data for the request
        print("VirusTotal responded successfully. The provided key appears to be accepted for requests.")
        sys.exit(0)
except Exception as e:
    print("Network or request error while contacting VirusTotal:", str(e))
    print("If this is a permissions or key problem, verify your VT_API_KEY value and try again.")
    sys.exit(5)
