# 🛠️ SentinelIQ Troubleshooting Guide

This guide covers common issues you may encounter while installing or running SentinelIQ and explains how to resolve them.



# 1. Python Command Not Found

## Problem

Running:

```bash
python app.py
```

returns:

```text
'python' is not recognized as an internal or external command
```

## Solution

- Install Python 3.11 or later.
- During installation, enable **Add Python to PATH**.
- Restart the terminal and verify the installation.

```bash
python --version
```



# 2. Missing Python Dependencies

## Problem

The application displays errors such as:

```text
ModuleNotFoundError
```

## Solution

Activate the virtual environment and reinstall the required packages.

```bash
venv\Scripts\activate

pip install -r requirements.txt
```



# 3. Flask Server Does Not Start

## Problem

Running:

```bash
python app.py
```

does not start the web server.

## Solution

Check that:

- The virtual environment is activated.
- All dependencies are installed.
- No syntax errors exist in the project files.

Restart the application.

```bash
python app.py
```



# 4. Dashboard Does Not Load

## Problem

Opening the browser shows:

```
This site can't be reached
```

## Solution

Verify that the Flask server is running.

Open:

```
http://127.0.0.1:5000
```

If the server is not running, restart it.



# 5. Log Files Are Not Processed

## Problem

Uploaded log files do not generate alerts.

## Solution

Ensure the uploaded file is one of the supported formats:

- auth.log
- syslog
- Apache access.log
- Windows Event Logs
- CSV exports

Unsupported or malformed log files may not produce results.



# 6. AI Summary Not Generated

## Problem

The AI Analysis section remains empty.

## Solution

Verify that:

- Logs have been uploaded or demo data has been loaded.
- Alerts have been generated.
- The AI analysis module is enabled.

Without security events, no AI summary will be produced.



# 7. Report Generation Fails

## Problem

No report is generated after clicking **Report**.

## Solution

Generate alerts first by:

- Uploading log files, or
- Clicking **Load Demo**

Reports require analyzed security events.



# Additional Tips

- Keep Python updated.
- Use a virtual environment.
- Install all dependencies from `requirements.txt`.
- Restart the application after making configuration changes.
- Verify that uploaded logs are supported before analysis.
  