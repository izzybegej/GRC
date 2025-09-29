"""
Windows Password Policy Scanner
This script checks Windows password settings and tells you if they're secure.
Tested 9/10/25 on win 11. 
Author: Izzy
Updated Committed: 9/29/25 - Added complexity check and compliance percentage, removed admin check. 
"""

import subprocess

def get_password_info():
    """
    Runs a Windows command to get password policy information.
    """
    print("Getting password policy from Windows...")
    
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
    
    # If not found, return 0
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
                # Extract the number
                parts = line.split()
                return int(parts[-1])
    
    return 0

def check_password_complexity():
    """
    Check if password complexity is enabled.
    Complexity means passwords must have:
    - Uppercase letters (A-Z)
    - Lowercase letters (a-z)  
    - Numbers (0-9)
    - Special characters (!@#$)
    
    This prevents weak passwords like '123456789' from being allowed.
    """
    print("Checking password complexity setting...")
    
    # Use PowerShell to check the Local Security Policy
    # This checks if complexity requirements are turned ON or OFF
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             'secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg /quiet; ' +
             'Select-String -Path C:\\Windows\\Temp\\secpol.cfg -Pattern "PasswordComplexity"'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Check if complexity is enabled (value = 1) or disabled (value = 0)
        if 'PasswordComplexity = 1' in result.stdout:
            return True
        else:
            return False
            
    except:
        print("(Could not determine complexity setting)")
        return None

def check_password_security(min_length, lockout_enabled, complexity_enabled):
    """
    Checks if the passwords meet compliance, give % score. 
    """
    print("\n" + "=" * 60)
    print("** SECURITY CHECK RESULTS **")
    print("=" * 60)
    
    # Track how many checks pass
    total_checks = 3  # number of compliance checks being run
    passed_checks = 0
    
    # --- CHECK 1: Password Length ---
    print(f"\n1. Minimum password length: {min_length} characters.")
    if min_length >= 8:
        print("    PASS: Length is secure (8 or more characters).")
        print("    NIST Control: PR.AA-01")
        length_status = "PASS"
        passed_checks += 1  # Add 1 to pass counter
    else:
        print("    FAIL: Length is too short (should be 8 or more).")
        print("    Security Risk: Weak passwords can be guessed easily.")
        length_status = "FAIL"
    
    # --- CHECK 2: Account Lockout ---
    print(f"\n2. Account lockout after failed attempts: {lockout_enabled}.")
    if lockout_enabled > 0 and lockout_enabled <= 10:
        print(f"    PASS: Accounts lock after {lockout_enabled} failed attempts.")
        print("    NIST Control: PR.AA-03")
        lockout_status = "PASS"
        passed_checks += 1  # Add 1 to pass counter
    else:
        if lockout_enabled == 0:
            print("   FAIL: Accounts never lock out.")
            print("   Security Risk: Attackers can guess password unlimited number of times.")
        else:
            print(f"  WARNING: Lockout threshold ({lockout_enabled}) is high.")
            print("   Recommendation: Should be between 5-10 attempts.")
        lockout_status = "FAIL"
    
    # --- CHECK 3: Password Complexity ---
    print(f"\n3. Password complexity requirements: ", end="")
    if complexity_enabled is None:
        print("Complexity setting is not set.")
        print("Please enable complexity setting.")
        complexity_status = "SKIP"
        total_checks += 1  
    elif complexity_enabled:
        print("ENABLED")
        print("   PASS: Passwords must include uppercase, lowercase, numbers, and symbols.")
        print("   ISO Control: A.9.4.3")
        complexity_status = "PASS"
        passed_checks += 1  # Add 1 to pass counter
    else:
        print("DISABLED")
        print("   FAIL: Passwords can be simple like '123456789'.")
        print("   Security Risk: Users can set weak passwords that are easily guessed.")
        complexity_status = "FAIL"
    
    # --- CALCULATE COMPLIANCE PERCENTAGE ---
    # Percent calc: (passed / total) × 100
    if total_checks > 0:
        compliance_percentage = (passed_checks / total_checks) * 100
    else:
        compliance_percentage = 0
    
    # --- OVERALL RESULT ---
    print("\n" + "=" * 60)
    print("** COMPLIANCE SUMMARY **")
    print("=" * 60)
    
    print(f"\n Compliance Score: {compliance_percentage:.1f}%")
    print(f"   ({passed_checks} out of {total_checks} checks passed)")
    
    # Overall pass/fail
    if length_status == "PASS" and lockout_status == "PASS" and complexity_status == "PASS":
        print("\n OVERALL STATUS: SECURE")
        print("   Your password policy meets security standards!")
        print("   Status: COMPLIANT")
    else:
        print("\n OVERALL STATUS: NEEDS IMPROVEMENT")
        print("   Your password policy has security gaps.")
        print("   Status: NON-COMPLIANT")
        
        # Display outcome
        print("\n   Issues found:")
        if length_status == "FAIL":
            print("   - Password length too short.")
        if lockout_status == "FAIL":
            print("   - Account lockout not properly configured.")
        if complexity_status == "FAIL":
            print("   - Password complexity requirements disabled.")
         if complexity_status == "NONE":
            print("   - Password complexity not set/undefined.")
    
    print("=" * 60)

def main():
    print("=" * 60)
    print("*** PASSWORD POLICY COMPLIANCE SCANNER ***")
    print("=" * 60)
    print("This tool checks if your Windows password settings are secure")
    print("against NIST Cybersecurity Framework and ISO 27001 standards.\n")
    
    # Step 1: Get the password information from Windows
    password_data = get_password_info()
    
    # Step 2: Find the specific values needed
    min_length = find_password_length(password_data)
    lockout_setting = find_lockout_setting(password_data)
    complexity_setting = check_password_complexity()
    
    # Step 3: Check if these values meet security standards
    check_password_security(min_length, lockout_setting, complexity_setting)
    
    """
    # Step 4: Show raw data for reference
    print("\n** RAW SYSTEM DATA **")
    print("(This is the output from 'net accounts' command)")
    print("-" * 60)
    print(password_data)
    print("-" * 60)
    """
    
    # Step 5: Educational information
    print("\n** COMPLIANCE STANDARDS REFERENCE **")
    print("-" * 60)
    print(" Minimum password length: 8+ characters (NIST PR.AA-01)")
    print(" Account lockout: 5-10 failed attempts (NIST PR.AA-03)")
    print(" Password complexity: ENABLED (ISO 27001 A.9.4.3)")
    print("\nThese checks help prevent:")
    print("- Brute force password attacks")
    print("- Weak password usage")
    print("- Unauthorized access attempts")
    print("-" * 60)

if __name__ == "__main__":
    main()
