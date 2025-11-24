"""
Local Webapp for Password Policy Scanner
This Streamlit App checks Windows password settings and tells you if they're secure.
Author: Izzy
"""

import streamlit as st
import json
from datetime import datetime
import subprocess
import sqlite3
import pandas as pd

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
    
def check_automatic_updates():
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             '$updates = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings; ' +
             'if ($updates.NotificationLevel -eq 4) { Write-Output "ENABLED" } else { Write-Output "DISABLED" }'],
            capture_output=True, text=True, timeout=10
        )
        
        if 'ENABLED' in result.stdout:
            return True
        else:
            return False
    except:
        return None
    
def check_uac_status():
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA | Select-Object -ExpandProperty EnableLUA'],
            capture_output=True, text=True, timeout=10
        )
        
        if '1' in result.stdout.strip():
            return True
        else:
            return False
    except:
        return None

def check_screen_lock_timeout():
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name ScreenSaveTimeOut | Select-Object -ExpandProperty ScreenSaveTimeOut'],
            capture_output=True, text=True, timeout=10
        )
        
        timeout = int(result.stdout.strip())
        # Timeout is in seconds, 15 minutes = 900 seconds
        if timeout > 0 and timeout <= 900:
            return True
        else:
            return False
    except:
        return None
    
def check_guest_account():
    try:
        result = subprocess.run(
            ['net', 'user', 'Guest'],
            capture_output=True, text=True, timeout=10
        )
        
        # Check if account is active or inactive
        if 'Account active' in result.stdout:
            for line in result.stdout.split('\n'):
                if 'Account active' in line:
                    if 'No' in line:
                        return True  # Guest disabled = pass
                    else:
                        return False  # Guest enabled = fail
        return None
    except:
        return None

def check_critical_services():
    try:
        # Check if Windows Defender service is running
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-Service -Name WinDefend | Select-Object -ExpandProperty Status'],
            capture_output=True, text=True, timeout=10
        )
        
        if 'Running' in result.stdout:
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

# --- PART 3: Database function ---
def setup_database():
    """
    Creates the database and tables if they don't exist.
    This runs once when the app starts.
    """
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            system_name TEXT,
            compliance_score REAL,
            overall_status TEXT
        )
    ''')
    
    # Create check_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS check_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            check_number INTEGER,
            check_name TEXT,
            control_id TEXT,
            status TEXT,
            current_value TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    ''')
    
    conn.commit()
    conn.close()

# --- PART 5: Save scan to database ---
def save_scan_to_database(scan_date, system_name, compliance_score, overall_status, check_results_list):
    """
    Saves a complete scan (summary + all check results) to database.
    
    check_results_list should be a list of dictionaries like:
    [
        {'check_number': 1, 'check_name': 'Password Length', 'control_id': 'PR.AA-01', 
         'status': 'FAIL', 'current_value': '6 characters'},
        ...
    ]
    """
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    # Insert scan summary
    cursor.execute('''
        INSERT INTO scans (scan_date, system_name, compliance_score, overall_status)
        VALUES (?, ?, ?, ?)
    ''', (scan_date, system_name, compliance_score, overall_status))
    
    # Get the scan_id that was just created
    scan_id = cursor.lastrowid
    
    # Insert all check results linked to this scan
    for check in check_results_list:
        cursor.execute('''
            INSERT INTO check_results (scan_id, check_number, check_name, control_id, status, current_value)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, check['check_number'], check['check_name'], 
              check['control_id'], check['status'], check['current_value']))
    
    conn.commit()
    conn.close()
    
    return scan_id

# --- PART 5: SCAN HISTORY
def get_scan_history(limit=10):
    """
    Retrieves the most recent scans from database.
    Returns a list of scan summaries.
    """
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT scan_id, scan_date, system_name, compliance_score, overall_status
        FROM scans
        ORDER BY scan_date DESC
        LIMIT ?
    ''', (limit,))
    
    scans = cursor.fetchall()
    conn.close()
    
    return scans


def get_scan_details(scan_id):
    """
    Gets all check results for a specific scan.
    """
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT check_number, check_name, control_id, status, current_value
        FROM check_results
        WHERE scan_id = ?
        ORDER BY check_number
    ''', (scan_id,))
    
    results = cursor.fetchall()
    conn.close()
    return results

# --- PART 6: Display in Streamlit ---


st.title("Password Policy Compliance Scanner")
st.write("Checking Windows password settings against NIST CSF and ISO 27001 standards")

# Initialize session state
setup_database()

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
        st.session_state.auto_updates = check_automatic_updates()
        st.session_state.uac = check_uac_status()
        st.session_state.screen_lock = check_screen_lock_timeout()
        st.session_state.guest_account = check_guest_account()
        st.session_state.services = check_critical_services()

    
    # Use stored values
    password_data = st.session_state.password_data
    password_data = get_password_info()
    min_length = st.session_state.min_length
    lockout = st.session_state.lockout
    complexity = st.session_state.complexity
    firewall = st.session_state.firewall
    file_permissions = st.session_state.file_permissions
    auto_updates = st.session_state.auto_updates
    uac = st.session_state.uac
    screen_lock = st.session_state.screen_lock
    guest_account = st.session_state.guest_account
    services = st.session_state.services


    # Count passes and fails for compliance percentage
    total_checks = 10
    passed_checks = 0
    
    # Track which checks passed
    length_pass = False
    lockout_pass = False
    complexity_pass = False
    firewall_pass = False
    file_permissions_pass = False
    auto_updates_pass = False
    uac_pass = False
    screen_lock_pass = False
    user_accounts_pass = False
    services_pass = False
    guest_account_pass = False
   
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

    if auto_updates == True:
        passed_checks += 1
        auto_updates_pass = True
    else:
        auto_updates_pass = False

    if uac == True:
        passed_checks += 1
        uac_pass = True
    else:
        uac_pass = False
  
    if screen_lock == True:
        passed_checks += 1
        screen_lock_pass = True
    else:
        screen_lock_pass = False
    
    if guest_account == True:
        passed_checks += 1
        guest_account_pass = True
    else:
        guest_account_pass = False

    if services == True:
        passed_checks += 1
        services_pass = True
    else:
        services_pass = False

    # Calculate compliance percentage
    if total_checks > 0:
        compliance_percent = (passed_checks / total_checks) * 100
    else:
        compliance_percent = 0
    
    # Display compliance summary at top
    st.subheader("Compliance Summary")
    
    # Setup for database save
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    system_name = "LocalSystem"  # You could make this dynamic later
    overall_status = "COMPLIANT" if compliance_percent == 100 else "NON-COMPLIANT"
    
    # Collect all check results
    check_results_list = [
        {'check_number': 1, 'check_name': 'Password Length', 'control_id': 'NIST PR.AA-01',
         'status': 'PASS' if length_pass else 'FAIL', 'current_value': f"{min_length} characters"},
        {'check_number': 2, 'check_name': 'Account Lockout', 'control_id': 'NIST PR.AA-03',
         'status': 'PASS' if lockout_pass else 'FAIL', 'current_value': f"{lockout} attempts" if lockout > 0 else "Never"},
        {'check_number': 3, 'check_name': 'Password Complexity', 'control_id': 'ISO A.9.4.3',
         'status': 'PASS' if complexity_pass else 'FAIL', 'current_value': 'Enabled' if complexity else 'Disabled'},
        {'check_number': 4, 'check_name': 'Windows Firewall', 'control_id': 'NIST PR.IR-01',
         'status': 'PASS' if firewall_pass else 'FAIL', 'current_value': 'Enabled' if firewall else 'Disabled'},
        {'check_number': 5, 'check_name': 'System Folder Permissions', 'control_id': 'ISO A.9.4.1',
         'status': 'PASS' if file_permissions_pass else 'FAIL', 'current_value': 'Secured' if file_permissions else 'Insecure'},
        {'check_number': 6, 'check_name': 'Automatic Updates', 'control_id': 'NIST PR.PS-02',
         'status': 'PASS' if auto_updates_pass else 'FAIL', 'current_value': 'Enabled' if auto_updates else 'Disabled'},
        {'check_number': 7, 'check_name': 'User Account Control', 'control_id': 'NIST PR.AA-05',
         'status': 'PASS' if uac_pass else 'FAIL', 'current_value': 'Enabled' if uac else 'Disabled'},
        {'check_number': 8, 'check_name': 'Screen Lock Timeout', 'control_id': 'NIST PR.AA-03',
         'status': 'PASS' if screen_lock_pass else 'FAIL', 'current_value': '15 min or less' if screen_lock else 'Too long/disabled'},
        {'check_number': 9, 'check_name': 'Guest Account', 'control_id': 'NIST PR.AA-05',
         'status': 'PASS' if guest_account_pass else 'FAIL', 'current_value': 'Disabled' if guest_account else 'Enabled'},
        {'check_number': 10, 'check_name': 'Critical Services', 'control_id': 'NIST PR.PS-04',
         'status': 'PASS' if services_pass else 'FAIL', 'current_value': 'Running' if services else 'Not running'}
    ]
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

    # Button to save scan to database
    if st.button("Save Scan to Database", type="secondary"):
        scan_id = save_scan_to_database(
            scan_date, 
            system_name, 
            compliance_percent, 
            overall_status, 
            check_results_list
        )
        st.success(f"Scan saved to database! Scan ID: {scan_id}")
    
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

# --- CHECK 6: Automatic Updates ---
    st.write("### Check 6: Automatic Updates")
    st.write("**Standard:** NIST CSF PR.PS-02 (Software Maintained and Updated)")
    
    if auto_updates == True:
        st.write("**Current Setting:** Enabled - Download and install automatically")
    elif auto_updates == False:
        st.write("**Current Setting:** Disabled or manual updates only")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Automatic updates enabled")
    
    if auto_updates_pass:
        st.success("STATUS: PASS - Automatic updates are enabled")
    elif auto_updates == None:
        st.warning("STATUS: UNKNOWN - Could not determine update settings")
        st.write("**Note:** Manual verification required or run as Administrator")
    else:
        st.error("STATUS: FAIL - Automatic updates are not enabled")
        st.write("**Security Risk:** Systems without automatic updates miss critical security patches, leaving vulnerabilities unaddressed")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment6 = st.text_area(
                "Compensating Control Documentation:",
                key="updates_comment",
                height=100,
                placeholder="Example: Production server uses managed update service with testing cycle. Compensating controls: Weekly security patch review process, emergency patching procedure for critical vulnerabilities, WSUS server manages deployment schedule."
            )
            if st.button("Save Comment", key="updates_save"):
                if comment6.strip():
                    save_comment("NIST PR.PS-02 - Automatic Updates", comment6)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

# --- CHECK 7: User Account Control ---
    st.write("### Check 7: User Account Control (UAC)")
    st.write("**Standard:** NIST CSF PR.AA-05 (Access Permissions with Least Privilege)")
    
    if uac == True:
        st.write("**Current Setting:** Enabled")
    elif uac == False:
        st.write("**Current Setting:** Disabled")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** UAC enabled to prompt for administrative actions")
    
    if uac_pass:
        st.success("STATUS: PASS - User Account Control is enabled")
    elif uac == None:
        st.warning("STATUS: UNKNOWN - Could not determine UAC status")
        st.write("**Note:** Manual verification required")
    else:
        st.error("STATUS: FAIL - User Account Control is disabled")
        st.write("**Security Risk:** Without UAC, malware can gain administrative privileges without user notification")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment7 = st.text_area(
                "Compensating Control Documentation:",
                key="uac_comment",
                height=100,
                placeholder="Example: Development environment requires UAC disabled for testing. Compensating controls: System isolated on development VLAN, endpoint protection with behavioral monitoring, standard user accounts for daily tasks, administrative access logged."
            )
            if st.button("Save Comment", key="uac_save"):
                if comment7.strip():
                    save_comment("NIST PR.AA-05 - User Account Control", comment7)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

# --- CHECK 8: Screen Lock Timeout ---
    st.write("### Check 8: Screen Lock Timeout")
    st.write("**Standard:** NIST CSF PR.AA-03 (Authentication and Access Control)")
    
    if screen_lock == True:
        st.write("**Current Setting:** Screen lock enabled (15 minutes or less)")
    elif screen_lock == False:
        st.write("**Current Setting:** Screen lock disabled or timeout too long")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Screen lock after 15 minutes or less of inactivity")
    
    if screen_lock_pass:
        st.success("STATUS: PASS - Screen lock timeout is properly configured")
    elif screen_lock == None:
        st.warning("STATUS: UNKNOWN - Could not determine screen lock settings")
        st.write("**Note:** Manual verification required")
    else:
        st.error("STATUS: FAIL - Screen lock timeout is not properly configured")
        st.write("**Security Risk:** Unattended workstations without automatic locking allow unauthorized physical access")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment8 = st.text_area(
                "Compensating Control Documentation:",
                key="screenlock_comment",
                height=100,
                placeholder="Example: Public kiosk requires no auto-lock for accessibility. Compensating controls: System has no access to sensitive data, all sessions timeout after 5 minutes of inactivity, physical security camera monitoring, guest account with restricted permissions."
            )
            if st.button("Save Comment", key="screenlock_save"):
                if comment8.strip():
                    save_comment("NIST PR.AA-03 - Screen Lock Timeout", comment8)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
 
    st.divider()

# --- CHECK 9: Guest Account Status ---
    st.write("### Check 9: Guest Account Disabled")
    st.write("**Standard:** NIST CSF PR.AA-05 (Access Permissions with Least Privilege)")
    
    if guest_account == True:
        st.write("**Current Setting:** Guest account is disabled")
    elif guest_account == False:
        st.write("**Current Setting:** Guest account is enabled")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Guest account must be disabled")
    
    if guest_account_pass:
        st.success("STATUS: PASS - Guest account is properly disabled")
    elif guest_account == None:
        st.warning("STATUS: UNKNOWN - Could not determine guest account status")
        st.write("**Note:** Manual verification required")
    else:
        st.error("STATUS: FAIL - Guest account is enabled")
        st.write("**Security Risk:** Enabled guest accounts allow unauthorized users to access the system without credentials")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment9 = st.text_area(
                "Compensating Control Documentation:",
                key="guest_comment",
                height=100,
                placeholder="Example: Public library computer requires guest access. Compensating controls: Guest account heavily restricted with minimal permissions, session timeout after 30 minutes, all activity logged and monitored, no access to network resources."
            )
            if st.button("Save Comment", key="guest_save"):
                if comment9.strip():
                    save_comment("NIST PR.AA-05 - Guest Account Disabled", comment9)
                    st.success("Comment saved successfully")
                    st.rerun()
                else:
                    st.warning("Please enter a comment before saving")
    
    st.divider()

# --- CHECK 10: Critical Services Status ---
    st.write("### Check 10: Critical Security Services")
    st.write("**Standard:** NIST CSF PR.PS-04 (Log Records Generated and Monitored)")
    
    if services == True:
        st.write("**Current Setting:** Windows Defender service is running")
    elif services == False:
        st.write("**Current Setting:** Windows Defender service is not running")
    else:
        st.write("**Current Setting:** Unknown")
    
    st.write("**Requirement:** Critical security services must be running")
    
    if services_pass:
        st.success("STATUS: PASS - Windows Defender service is active")
    elif services == None:
        st.warning("STATUS: UNKNOWN - Could not check service status")
        st.write("**Note:** Manual verification required or run as Administrator")
    else:
        st.error("STATUS: FAIL - Windows Defender service is not running")
        st.write("**Security Risk:** Critical security services not running leaves system unprotected from threats")
        
        with st.expander("Add Compensating Control Comment"):
            st.write("Document why this system cannot meet the requirement and what alternative controls are in place:")
            comment10 = st.text_area(
                "Compensating Control Documentation:",
                key="services_comment",
                height=100,
                placeholder="Example: Windows Defender disabled due to enterprise antivirus deployment. Compensating controls: CrowdStrike Falcon installed and monitored centrally, EDR active on all endpoints, security operations center monitoring alerts 24/7."
            )
            if st.button("Save Comment", key="services_save"):
                if comment10.strip():
                    save_comment("NIST PR.PS-04 - Critical Services", comment10)
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
            del st.session_state.auto_updates
            del st.session_state.uac
            del st.session_state.screen_lock
            del st.session_state.guest_account
            del st.session_state.services
        st.rerun()

else:
    st.info("Click 'Run Compliance Scan' to check password policies against security standards")

# --- SCAN HISTORY SECTION ---

# --- SCAN HISTORY COMPARISON TABLE ---

st.divider()
st.subheader("Scan History - Compliance Comparison")

scans = get_scan_history(limit=5)  # Show last 5 scans

if scans:
    # Build data for table
    table_data = []
    check_names = [
        "Password Length",
        "Account Lockout", 
        "Password Complexity",
        "Windows Firewall",
        "System Folder Permissions",
        "Automatic Updates",
        "User Account Control",
        "Screen Lock Timeout",
        "Guest Account",
        "Critical Services"
    ]
    
    for check_num, check_name in enumerate(check_names, 1):
        row = {"Check": f"{check_num}. {check_name}"}
        
        for scan in scans:
            scan_id, scan_date, system_name, compliance_score, overall_status = scan
            details = get_scan_details(scan_id)
            
            # Find this check's result
            for detail in details:
                detail_check_num, detail_check_name, control_id, status, current_value = detail
                if detail_check_num == check_num:
                    row[f"Scan {scan_id}\n{scan_date}"] = f"{status}\n({current_value})"
                    break
        
        table_data.append(row)
    
    # Add compliance scores row
    compliance_row = {"Check": "Overall Compliance"}
    for scan in scans:
        scan_id, scan_date, system_name, compliance_score, overall_status = scan
        compliance_row[f"Scan {scan_id}\n{scan_date}"] = f"{compliance_score:.1f}%"
    table_data.append(compliance_row)
    
    # Display as table
    df = pd.DataFrame(table_data)
    st.dataframe(df, width='stretch', hide_index=True)
    
else:
    st.info("No scan history yet. Run a scan and click 'Save to Database' to start tracking.")
