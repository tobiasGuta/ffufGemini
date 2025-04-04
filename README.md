# ffufGemini

Description:

This Python script automates web application fuzzing using ffuf, with Gemini AI-powered file extension suggestions. It detects technologies on the target website with httpx, uses Gemini's AI to suggest file extensions based on those technologies, and runs ffuf to discover potential hidden files. The script is designed for bug bounty hunters, penetration testers, and security researchers who want to enhance their fuzzing techniques.

## Features:

Technology detection using httpx

AI-powered extension suggestion via Gemini API

Automated file fuzzing with ffuf

Handles target URLs with FUZZ placeholders for fuzzing

## How to Use:

Install the necessary dependencies: httpx, ffuf, and requests.

Set up your Gemini API key as an environment variable (GEMINI_API_KEY).
```bash
export GEMINI_API_KEY="Gemini_Key"
```

Run the script with the target URL and wordlist.

```
python3 ffuGemini.py -u "https://example.com/FUZZ" -w /path/to/wordlist.txt
```
