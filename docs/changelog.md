## Changelog
Reverse chronological order.
### Sprint 6 (Nov 1-15, 2024)
#### Added
5 additional compliance checks to scanner-app.py:
- Check 6: Automatic Updates (NIST PR.PS-02)
- Check 7: User Account Control/UAC (NIST PR.AA-05)
- Check 8: Screen Lock Timeout (NIST PR.AA-03)
- Check 9: Guest Account Disabled (NIST PR.AA-05)
- Check 10: Critical Services Status (NIST PR.PS-04)

#### Updated
- Standardized pass/fail logic with explicit else statements for all checks
- Changed "Unknown" status to count as FAIL for compliance scoring
- Total compliance checks: 10 (up from 5)
- Improved code consistency across all checks

### Sprint 5 (Oct 13-31, 2024)
#### Added
2 new compliance checks to scanner-app.py:
- Check 4: Windows Firewall Status (NIST PR.IR-01 / ISO A.9.1.2)
- Check 5: System Folder Permissions (ISO A.9.4.1)

Project presentation delivered (Oct 27)

#### Updated
- Implemented session state management for persistent display across button clicks
- Fixed compliance percentage calculation logic
- Comments now persist correctly with st.rerun() implementation
- Added proper cleanup on "Run New Scan" button
- Enhanced error handling for unknown/null check results

#### Technical Improvements
- Session state prevents scan results from disappearing when saving comments
- Persistent storage now functional for compensating control documentation


### Sprint 4 (Sept 30- Oct 12, 2024)
#### Updated
- Created streamlit app for password-policy.py (runs locally)
- Added compensatory note section for non-compliant results.
- .json file creation for compensating control history  

### Sprint 3 (Sept 15-29, 2024)
#### Updated
- Check for compliance
- Added scoring system
- Removed check for admin access; can run on least privilege
- Narrowed Scope
- Reviewed similar solutions to determine next steps
  
### Sprint 2 (Sept 8-14, 2024)
#### Added
3 compliance checks added to scanner-app.py:
- Check 1: Minimum Password Length (NIST PR.AA-01)
- Check 2: Account Lockout Policy (NIST PR.AA-03)
- Check 3: Password Complexity Requirements (ISO A.9.4.3)


NIST framework research (NIST-Research.md)



### Sprint 1 (Sept 1-7, 2024)
#### Added
- Initial project structure (Architecture.md)
- NIST framework research (No commit)
- Project scope definition (Readme.md)
