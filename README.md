# SecureScan — File Malware Scanner

A web application that allows users to upload files and scan them for malware using the VirusTotal API, with AI-powered plain-English explanations via Google Gemini.

## Live Demo

http://3.145.190.82:5000

## Features

- Upload files (txt, pdf, png, jpg, jpeg, gif, zip, exe, doc, docx) up to 32MB
- Scan files against 70+ antivirus engines via VirusTotal API
- View detailed scan results including malicious, suspicious, and clean detections
- Get a plain-English AI explanation of the results powered by Google Gemini

## Tech Stack

- **Backend:** Python, Flask
- **APIs:** VirusTotal API, Google Gemini API
- **Hosting:** AWS EC2 (Amazon Linux 2023, t2.micro)

## Setup Instructions

### Prerequisites

- Python 3.9+
- A [VirusTotal API key](https://www.virustotal.com) (free)
- A [Gemini API key](https://aistudio.google.com) (free)

### Local Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/sophiewang8425/webtest.git
   cd webtest
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # Mac/Linux
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the root folder:
   ```
   VIRUSTOTAL_API_KEY=your_virustotal_key_here
   GEMINI_API_KEY=your_gemini_key_here
   ```

5. Create the uploads folder:
   ```bash
   mkdir uploads
   ```

6. Run the app:
   ```bash
   python app.py
   ```

7. Open your browser and go to `http://127.0.0.1:5000`

### AWS EC2 Deployment

1. Launch a t2.micro EC2 instance (Amazon Linux 2023)
2. Open port 5000 in the security group inbound rules
3. SSH into the instance and install dependencies:
   ```bash
   sudo dnf install python3-pip git -y
   pip3 install flask python-dotenv requests google-generativeai
   ```
4. Transfer files using `scp` and run `python3 app.py`

## How It Works

1. User uploads a file through the web interface
2. The file is sent to VirusTotal API for scanning
3. The app polls VirusTotal until the scan is complete (~30 seconds)
4. Scan results are displayed showing detections from each antivirus engine
5. User can click "Explain in plain English" to get a Gemini AI summary

## Security Considerations

- Files are deleted from the server immediately after scanning
- File types are validated before upload
- API keys are stored in environment variables, never in code
- Filenames are sanitized using werkzeug's `secure_filename`
