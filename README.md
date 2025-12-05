# Password Configuration Scanner

**Project Start Date:** September 5, 2025  
**Expected Completion:** December 2, 2025  

## Project Overview

An automated Python tool that scans computer systems to check if they follow security rules from NIST and ISO 27001 frameworks.

## The Problem to Solve

- Some IT security teams are still manually checking each workstation for security problems.
- Companies only know if systems are secure during audit time, not year-round.
- Technical reports are hard for business leaders to understand, which can lead to delay in compliance if there is not clear impact on the business.
- Variable tracking if security fixes actually get done. IT teams find it hard to show ROI.

## What This Tool Does

1. **Scan Systems Automatically** - Check Windows computers for compliance on 10 different security settings against NIST CSF and ISO 27001 standards.
2. **Compliance Tracking** - Stores scan history in database to track compliance improvements over time.
3. **Compensating Control Documentation** - When a setting is non-compliant, the user can document why the system can't meet requirements. Allows for documentation of alternative controls in place.
4. **Easy To Read Reporting** - Provides compliance percentage scores and table for visual comparison across scan history.


## Technology Stack

- **Language:** Python 3.9+
- **Webapp** Streamlit (browser based interface)
- **Key Libraries:** pandas (data handling), subprocess (system commands), sqlite3 (database storage)
- **Storage:** JSON files and SQLite database
- **Security:** Least privilege execution, read-only system queries, no administrator rights required

## Features

### Compliance Checks (10 Total)
- Password Length (NIST PR.AA-01)
- Account Lockout Policy (NIST PR.AA-03)
- Password Complexity (ISO 27001 A.9.4.3)
- Windows Firewall Status (NIST PR.IR-01 / ISO A.9.1.2)
- System Folder Permissions (ISO 27001 A.9.4.1)
- Automatic Updates (NIST PR.PS-02)
- User Account Control (NIST PR.AA-05)
- Screen Lock Timeout (NIST PR.AA-03)
- Guest Account Status (NIST PR.AA-05)
- Critical Services / Windows Defender (NIST PR.PS-04)

### Key Capabilities
- **Real-time Scanning:** Run compliance checks on-demand
- **Historical Tracking:** Compare up to 5 past scans
- **Compliance Scoring:** Calculates of compliance percentage
- **Compensating Controls:** Document exceptions and alternative security measures
- **Persistent Storage:** All scan results saved to SQLite database for audit trail

## Security Considerations

This tool handles sensitive system configuration data. All development follows secure coding practices:
- Least privilege execution (use of net accounts)
- Input validation and sanitization
- Encrypted data storage
- Comprehensive audit logging
- No hardcoded credentials or secrets

## Learning Resources Used
- NIST Cybersecurity Framework 2.0
- ISO 27001 Annex A Controls
- Python subprocess documentation
- OWASP Guide

## License

No licensing available at the moment. 

Contact: grc-scanner.fresh299@passmail.com
