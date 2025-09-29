# Password Configuration Scanner

**Project Start Date:** September 5, 2025  
**Expected Completion:** December 2, 2025  

## Project Overview

An automated Python tool that scans computer systems to check if they follow security rules from NIST and ISO 27001 frameworks.

## The Problem to Solve

- Some IT security teams are still manually checking each workstation for security problems.
- Companies only know if systems are secure during audit time, not year-round
- Technical reports are hard for business leaders to understand, which can lead to delay in compliance if there is not clear impact on the business for lack of compliance.
- Variable tracking if security fixes actually get done. IT teams find it hard to show ROI.

## What This Tool Will Do

1. **Scan Systems Automatically** - Check Windows and (later) Linux computers for security settings
2. **Check Against Standards** - Compare findings to NIST and ISO 27001 requirements


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
- [X] Work on scanner: Win 11 password policy compliance
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
