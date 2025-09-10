"""
Windows Password Policy Scanner
This script checks Windows password settings and tells you if they're secure.
Tested 9/10/25 on win 11. 
Author: Izzy
"""

import subprocess

def get_password_info():
    """
       Runs a Windows command to get password policy information.
    """
    print("Getting password policy from Windows...")
    
    # Run the Windows command 'net accounts'
    # subprocess.run() lets Python run Windows commands 
    result = subprocess.run(['net', 'accounts'], capture_output=True, text=True)
    
    # Return the text output from the command
    return result.stdout

def find_password_length(text):
    """
    This function looks through the text to find the minimum password length.
    """
    # Split the text into individual lines
    lines = text.split('\n')
    
    # Look through each line
    for line in lines:
        # Check if this line talks about password length
        if 'Minimum password length:' in line:
            # Split the line by spaces and get the last part (the number)
            parts = line.split()
            length = parts[-1]  # -1 means "last item in the list"
            return int(length)  # Convert text to number
    
    # If we didn't find it, return 0
    return 0

def find_lockout_setting(text):
    """
    This function finds if accounts get locked after incorrect passwords are tried.
    """
    lines = text.split('\n')
    
    for line in lines:
        if 'Lockout threshold:' in line:
            # Check if it says "Never"
            if 'Never' in line:
                return 0
            else:
                # Extract the number (this is more complex, we'll simplify)
                parts = line.split()
                return int(parts[-1])
    
    return 0

def check_password_security(min_length, lockout_enabled):
    """
    This function decides if the password settings are good or bad.
    """
    print("\n** Security Check Results **")
    
    # Check password length
    print(f"Minimum password length: {min_length}")
    if min_length >= 8:
        print("GOOD: Password length is secure (8 or more characters)")
        length_status = "PASS"
    else:
        print("BAD: Password length is too short (should be 8 or more)")
        length_status = "FAIL"
    
    # Check account lockout
    print(f"\nAccount lockout after failed attempts: {lockout_enabled}")
    if lockout_enabled > 0:
        print(f"GOOD: Accounts lock after {lockout_enabled} failed attempts")
        lockout_status = "PASS"
    else:
        print("BAD: Accounts never lock (should lock after 5-10 attempts)")
        lockout_status = "FAIL"
    
    # Overall result
    if length_status == "PASS" and lockout_status == "PASS":
        print("\nOVERALL: Your password policy is SECURE!")
    else:
        print("\nOVERALL: Your password policy needs improvement")

def main():
    print("*** Password Policy Scanner ***")
    print("This tool checks if your Windows password settings are secure.\n")
    
    # 1: Get the password information from Windows
    password_data = get_password_info()
    
    # 2: Find the specific values for password legnth and user lockout
    min_length = find_password_length(password_data)
    lockout_setting = find_lockout_setting(password_data)
    
    # 3: Check if these values are secure per NIST
    check_password_security(min_length, lockout_setting)
    
    # 4: Show the current sys settings
    print("\n** Current Security Settings **")
    print(password_data)
    
    print("\n** Learning Notes **")
    print("- Minimum password length should be 8+ characters")
    print("- Account lockout should be enabled (5-10 failed attempts)")
    print("- Maps to NIST control PR.AA-01")

if __name__ == "__main__":
    main()
