# GRC
Security Scanner for GRC Compliance 

# Compliance Configuration Scanner (CCS)

**Project Start Date:** September 5, 2024  
**Expected Completion:** December 2, 2024  

## Project Overview

An automated Python tool that scans computer systems to check if they follow security rules from NIST and ISO 27001 frameworks. This tool will replace manual security audits that take weeks with automated scans that take hours.

## The Problem to Solve

- Some IT security teams are still manually checking each workstation for security problems.
- Companies only know if systems are secure during audit time, not year-round
- Technical reports are hard for business leaders to understand, which can lead to delay in compliance if there is not clear impact on the business for lack of compliance.
- Variable tracking if security fixes actually get done. IT teams find it hard to show ROI.

## What This Tool Will Do

1. **Scan Systems Automatically** - Check Windows and (later) Linux computers for security settings
2. **Check Against Standards** - Compare findings to NIST and ISO 27001 requirements  
3. **Create Professional Reports** - Generate PDF reports for managers and IT teams
4. **Track Security Over Time** - Store results to show if security is getting better or worse
5. **Secure by Design** - Built with security best practices from day one

## Target Security Controls

### Windows Systems
- Password policy enforcement
- User account management
- Windows Firewall status
- System service configurations
- Registry security settings

### Linux Systems (Part 2)
- File permission settings
- SSH configuration security
- Firewall rules and status
- User account policies
- System update status

## Technology Stack

- **Language:** Python 3.9+
- **Key Libraries:** pandas (data handling), subprocess (system commands), cryptography (security)
- **Reports:** ReportLab for PDF generation
- **Storage:** Encrypted JSON files and SQLite database
- **Security:** Input validation, encrypted storage, audit logging

## Project Status

**Week 1 - Framework Research** (In Progress)
- [ ] Learn NIST Cybersecurity Framework
- [ ] Study ISO 27001 security controls
- [ ] Define target controls for automation
- [ ] Create project scope document

## Installation

*Coming in Week 2*

## Usage

*Coming in Week 3*

## Security Considerations

This tool handles sensitive system configuration data. All development follows secure coding practices:
- Least privilege execution
- Input validation and sanitization
- Encrypted data storage
- Comprehensive audit logging
- No hardcoded credentials or secrets

## License

No licensing available at the moment. 

Contact: grc-scanner.fresh299@passmail.com
