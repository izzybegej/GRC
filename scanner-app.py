"""
Local Webapp for Password Policy Scanner
This Streamlit App checks Windows password settings and tells you if they're secure.
Author: Izzy
"""

import streamlit as st
import json
from datetime import datetime
import subprocess

# --- PART 1: Run the password checks (from password-policy.py) ---

def get_password_info():
    result = subprocess.run(['net', 'accounts'], capture_output=True, text=True)
    return result.stdout

def find_password_length(text):
    lines = text.split('\n')
    for line in lines:
        if 'Minimum password length:' in line:
            parts = line.split()
            return int(parts[-1])
    return 0

def find_lockout_setting(text):
    lines = text.split('\n')
    for line in lines:
        if 'Lockout threshold:' in line:
            if 'Never' in line:
                return 0
            else:
                parts = line.split()
                return int(parts[-1])
    return 0

def check_password_complexity():
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             'secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg /quiet; ' +
             'Select-String -Path C:\\Windows\\Temp\\secpol.cfg -Pattern "PasswordComplexity"'],
            capture_output=True, text=True, timeout=10
        )
        if 'PasswordComplexity = 1' in result.stdout:
            return True
        else:
            return False
    except:
        return None

def check_firewall_status():
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             'Get-NetFirewallProfile | Select-Object Name, Enabled'],
            capture_output=True, text=True, timeout=10
        )
        
        # Check if all profiles show "True" for enabled
        if result.stdout.count('True') >= 3:
            return True
        else:
            return False
    except:
        return None
    
def check_system_folder_permissions():
    try:
        # Check if regular users can modify System32
        result = subprocess.run(
            ['powershell', '-Command',
             '$acl = Get-Acl "C:\\Windows\\System32"; ' +
             '$userAccess = $acl.Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Modify|FullControl"}; ' +
             'if ($userAccess) { Write-Output "FAIL" } else { Write-Output "PASS" }'],
            capture_output=True, text=True, timeout=10
        )
        
        if 'PASS' in result.stdout:
            return True
        else:
            return False
    except:
        return None



# --- PART 2: Save and load comments ---

def save_comment(control_name, comment_text):
    try:
        with open('comments.json', 'r') as f:
            all_comments = json.load(f)
    except:
        all_comments = []
    
    all_comments.append({
        'control': control_name,
        'comment': comment_text,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M')
    })
    
    with open('comments.json', 'w') as f:
        json.dump(all_comments, f, indent=2)

# --- PART 3: Display in Streamlit ---


st.title("Password Policy Compliance Scanner")
st.write("Checking Windows password settings against NIST CSF and ISO 27001 standards")

# Initialize session state
if 'scan_complete' not in st.session_state:
    st.session_state.scan_complete = False

# Button to run the scan
if st.button("Run Compliance Scan", type="primary"):
    st.session_state.scan_complete = True
    if 'password_data' in st.session_state:
        del st.session_state.password_data
    st.rerun()

if st.session_state.scan_complete:
    
    # Get the data from Windows
    if 'password_data' not in st.session_state:
        st.session_state.password_data = get_password_info()
        st.session_state.min_length = find_password_length(st.session_state.password_data)
        st.session_state.lockout = find_lockout_setting(st.session_state.password_data)
        st.session_state.complexity = check_password_complexity()
        st.session_state.firewall = check_firewall_status()
        st.session_state.file_permissions = check_system_folder_permissions()
    
    # Use stored values
    password_data = st.session_state.password_data
    password_data = get_password_info()
    min_length = st.session_state.min_length
    lockout = st.session_state.lockout
    complexity = st.session_state.complexity
    firewall = st.session_state.firewall
    file_permissions = st.session_state.file_permissions

    # Count passes and fails for compliance percentage
    total_checks = 5
    passed_checks = 0
    
    # Track which checks passed
    length_pass = False
    lockout_pass = False
    complexity_pass = False
    firewall_pass = False
    file_permissions_pass = False
   
    if 'password_data' not in st.session_state:
        st.session_state.password_data = get_password_info()
        st.session_state.min_length = find_password_length(...)


    # Determine pass/fail for each
    if min_length >= 8:
        passed_checks += 1
        length_pass = True
    else:
        length_pass = False
    
    if lockout > 0 and lockout <= 10:
        passed_checks += 1
        lockout_pass = True
    else:
        lockout_pass = False
    
    if complexity == True:
        passed_checks += 1
        complexity_pass = True
    else:
        complexity_pass = False
    
    if firewall == True:
        passed_checks += 1
        firewall_pass = True
    else: 
        firewall_pass = False

    if file_permissions == True:
        passed_checks += 1
        file_permissions_pass = True
    else:
        file_permissions_pass = False


    # Calculate compliance percentage
    if total_checks > 0:
        compliance_percent = (passed_checks / total_checks) * 100
    else:
        compliance_percent = 0
    
    # Display compliance summary at top
    st.subheader("Compliance Summary")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Compliance Score", f"{compliance_percent:.1f}%")
    with col2:
        st.metric("Checks Passed", f"{passed_checks} of {total_checks}")
    with col3:
        if compliance_percent == 100:
            st.success("**Status:** COMPLIANT")
        else:
            st.error("**Status:** NON-COMPLIANT")
    
    st.divider()
    st.subheader("Detailed Results")
    
    # --- CHECK 1: Password Length --- 

    st.write("### Check 1: Minimum Password Length")
    st.write("**Standard:** NIST CSF PR.AA-01 (Identity Management & Access Control)")
    st.write(f"**Current Setting:** {min_length} characters")
    st.write(f"**Requirement:** 8 or more characters")
    
    if length_pass:
        st.success("STATUS: PASS - Password length meets security requirements")
    else:
        st.error("STATUS: FAIL - Password length is below minimum requirement")
        st.write("**Security Risk:** Weak passwords can be guessed easily through brute force attacks")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment1 = st.text_area(
                "Compensating Control Documentation:",
                key="length_comment",
                height=100,
                placeholder="Example: Legacy application requires shorter passwords. Compensating controls: MFA enabled for all accounts, session timeout set to 15 minutes, all login attempts logged and monitored."
            )
            if st.button("Save Comment", key="length_save"):
                if comment1.strip():
                    save_comment("NIST PR.AA-01 - Password Length", comment1)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()
    

    # --- CHECK 2: Account Lockout ---

    st.write("### Check 2: Account Lockout Policy")
    st.write("**Standard:** NIST CSF PR.AA-03 (Authentication & Access Control)")
    
    if lockout == 0:
        st.write(f"**Current Setting:** Never locks out")
    else:
        st.write(f"**Current Setting:** Locks after {lockout} failed attempts")
    
    st.write(f"**Requirement:** 5-10 failed attempts")
    
    if lockout_pass:
        st.success("STATUS: PASS - Account lockout policy is properly configured")
    else:
        st.error("STATUS: FAIL - Account lockout is not properly configured")
        if lockout == 0:
            st.write("**Security Risk:** Attackers can attempt unlimited password guesses without consequence")
        else:
            st.write(f"**Security Risk:** Lockout threshold of {lockout} attempts is outside recommended range")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment2 = st.text_area(
                "Compensating Control Documentation:",
                key="lockout_comment",
                height=100,
                placeholder="Example: Business requirement prevents lockout policy due to shared service accounts. Compensating controls: All failed login attempts trigger alerts to security team, rate limiting implemented at network level, enhanced monitoring with automated blocking of suspicious IPs."
            )
            if st.button("Save Comment", key="lockout_save"):
                if comment2.strip():
                    save_comment("NIST PR.AA-03 - Account Lockout", comment2)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()
    
    # --- CHECK 3: Password Complexity ---
    st.write("### Check 3: Password Complexity Requirements")
    st.write("**Standard:** ISO 27001 A.9.4.3 (Password Management System)")
    
    if complexity == True:
        st.write("**Current Setting:** Enabled")
    elif complexity == False:
        st.write("**Current Setting:** Disabled")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Enabled (must include uppercase, lowercase, numbers, and symbols)")
    
    if complexity_pass:
        st.success("STATUS: PASS - Password complexity requirements are enabled")
    elif complexity == None:
        st.warning("STATUS: UNKNOWN - Could not determine complexity setting")
        st.write("**Note:** Manual verification required")
    else:
        st.error("STATUS: FAIL - Password complexity requirements are disabled")
        st.write("**Security Risk:** Users can create simple passwords like '123456789' that are easily compromised")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment3 = st.text_area(
                "Compensating Control Documentation:",
                key="complexity_comment",
                height=100,
                placeholder="Example: System does not support complexity requirements due to technical limitations. Compensating controls: 16-character minimum password length enforced, passwords changed every 60 days, password dictionary checking implemented to block common passwords."
            )
            if st.button("Save Comment", key="complexity_save"):
                if comment3.strip():
                    save_comment("ISO 27001 A.9.4.3 - Password Complexity", comment3)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

    # --- CHECK 4: Windows Firewall ---
    st.write("### Check 4: Windows Firewall Status")
    st.write("**Standards:** NIST CSF PR.IR-01 (Network Protection) / ISO 27001 A.9.1.2 (Network Access Control)")
    
    if firewall == True:
        st.write("**Current Setting:** Enabled on all profiles")
    elif firewall == False:
        st.write("**Current Setting:** Disabled on one or more profiles")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Enabled on all network profiles (Domain, Private, Public)")
    
    if firewall_pass:
        st.success("STATUS: PASS - Windows Firewall is enabled on all profiles")
    elif firewall == None:
        st.warning("STATUS: UNKNOWN - Could not determine firewall status")
        st.write("**Note:** Manual verification required")
    else:
        st.error("STATUS: FAIL - Windows Firewall is not enabled on all profiles")
        st.write("**Security Risk:** Systems without firewall protection are vulnerable to network-based attacks")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment4 = st.text_area(
                "Compensating Control Documentation:",
                key="firewall_comment",
                height=100,
                placeholder="Example: Windows Firewall disabled due to third-party firewall solution. Compensating controls: Alternate firewall deployed at network perimeter."
            )
            if st.button("Save Comment", key="firewall_save"):
                if comment4.strip():
                    save_comment("NIST PR.IR-01 / ISO A.9.1.2 - Windows Firewall", comment4)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

# --- CHECK 5: System Folder Permissions ---
    st.write("### Check 5: Critical System Folder Permissions")
    st.write("**Standard:** ISO 27001 A.9.4.1 (Information Access Restriction)")
    
    if file_permissions == True:
        st.write("**Current Setting:** Properly secured - Users cannot modify System32")
    elif file_permissions == False:
        st.write("**Current Setting:** Improperly configured - Users have modify access for System32")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Regular users should NOT have modify/write access to C:\\Windows\\System32")
    
    if file_permissions_pass:
        st.success("STATUS: PASS - System folders are properly secured")
    elif file_permissions == None:
        st.warning("STATUS: UNKNOWN - Could not determine file permissions")
        st.write("**Note:** Manual verification required or run as Administrator")
    else:
        st.error("STATUS: FAIL - Regular users have excessive permissions on system folders")
        st.write("**Security Risk:** Users with modify access to system folders can replace critical files, install malware, or compromise system integrity")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment5 = st.text_area(
                "Compensating Control Documentation:",
                key="permissions_comment",
                height=100,
                placeholder="Example: Development workstation requires elevated user permissions. Compensating controls: Intrusion detection system monitoring file changes, full disk encryption enabled."
            )
            if st.button("Save Comment", key="permissions_save"):
                if comment5.strip():
                    save_comment("ISO 27001 A.9.4.1 - System Folder Permissions", comment5)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

    if st.button("Run New Scan"):
        st.session_state.scan_complete = False
        if 'password_data' in st.session_state:
            del st.session_state.password_data
            del st.session_state.min_length
            del st.session_state.lockout
            del st.session_state.complexity
            del st.session_state.firewall
            del st.session_state.file_permissions
        st.rerun()

else:
    st.info("Click 'Run Compliance Scan' to check password policies against security standards")

# --- SAVED COMMENTS SECTION ---

st.divider()
st.subheader("Saved Compensating Control Comments")

try:
    with open('comments.json', 'r') as f:
        saved_comments = json.load(f)
    
    if saved_comments:
        for comment in saved_comments:
            st.write(f"**Control:** {comment['control']}")
            st.write(f"**Date Documented:** {comment['date']}")
            st.write(f"**Compensating Control:** {comment['comment']}")
            st.divider()
    else:
        st.info("No compensating control comments documented yet")
except:
    st.info("No compensating control comments documented yet")