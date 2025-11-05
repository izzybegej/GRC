# Installation Guide

## Requirements
- Python 3.9+
- Windows 10/11 or Linux

## Setup & Configuration

### Step 1: Install Required Python Packages
Open Command Prompt and run:
```bash
pip install streamlit
```

### Step 2: Download the Scanner Files
Save both files to the same folder:
- `password_scanner.py` (your original scanner)
- `scanner_app.py` (the Streamlit interface)

Recommended location:
```
C:\Users\[YourName]\Documents\GRC\scanner\
```

### Step 3: Run the Application
Navigate to your scanner folder:
```bash
cd C:\Users\[YourName]\Documents\GRC\scanner
```

Start the web interface:
```bash
python -m streamlit run scanner_app.py
```

Your browser will open automatically to `http://localhost:8501`

### Step 4: Use the Scanner
1. Click "Run Compliance Scan" button
2. Review the results
3. Add compensating control comments for any failed checks
4. Comments are saved to `comments.json` in the same folder

## Troubleshooting

**If you see "ModuleNotFoundError: No module named 'streamlit'":**
```bash
python -m pip install streamlit
```

**If the scan button doesn't work:**
- Make sure you're running Command Prompt as Administrator

**If browser doesn't open automatically:**
- Manually go to: http://localhost:8501

## Note
*Microsoft is ending support of Windows 10 on October 14, 2025.
This means workstations running Win10 will no longer receive security updates or tech support. 
Systems will be more vulnerable to threats. Microsoft is encouraging users to upgrade to Windows 11 prior to this date.*


