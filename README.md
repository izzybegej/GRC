# Password Configuration Scanner

**Project Start Date:** September 5, 2025  
**Expected Completion:** December 2, 2025  

## Project Overview

An automated Python tool that scans computer systems to check if they follow security rules from NIST and ISO 27001 frameworks. This tool will replace manual security audits that take weeks with automated scans that take hours.

## The Problem to Solve

- Some IT security teams are still manually checking each workstation for security problems.
- Companies only know if systems are secure during audit time, not year-round
- Technical reports are hard for business leaders to understand, which can lead to delay in compliance if there is not clear impact on the business for lack of compliance.
- Variable tracking if security fixes actually get done. IT teams find it hard to show ROI.

## What This Tool Will Do

### [X] TODO: Reword 1, as this is more of a password policy 
### [] TODO: Figure out how to get the standards in here. Look at Cynomi (vCISO as a service)
### [] TODO: Look into HIPAA, PCI-DDS, FERPA
1. **Scan Systems Automatically** - Check Windows and (later) Linux computers for security settings
2. **Check Against Standards** - Compare findings to NIST and ISO 27001 requirements
3. **Create Professional Reports** - Generate PDF reports for managers and IT teams
4. **Track Security Over Time** - Store results to show if security is getting better or worse
5. **Secure by Design** - Built with security best practices from day one

## Target Security Controls
### NOTE: You might want to punt this

### Windows Systems
- Password policy enforcement
- User account management
- Windows Firewall status
- System service configurations
- Registry security settings

## Technology Stack

- **Language:** Python 3.9+
- **Key Libraries:** pandas (data handling), subprocess (system commands), cryptography (security)
- **Reports:** ReportLab for PDF generation
- **Storage:** Encrypted JSON files and SQLite database
- **Security:** Input validation, encrypted storage, audit logging

## Project Status

Framework Research
- [X] Learn NIST Cybersecurity Framework
- [X] Study ISO 27001 security controls
- [X] Define target controls for automation
- [X] Create project scope document

## Installation
- [ ] Work on scanner: Win 11 password policy compliance
- [ ] Mapping for basic compliance
- [ ] JSON storage implementations 

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

## License

No licensing available at the moment. 

Contact: grc-scanner.fresh299@passmail.com
