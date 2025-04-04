import argparse
import subprocess
import json
import os
import requests
import sys
import re

# Function to get suggested extensions from Gemini
def get_ai_extensions(url, headers, api_key, tech_detected, max_extensions=5):
    tech_detected_str = ", ".join(tech_detected)  # Convert list to string for the prompt
    prompt = (
        f"You are an AI assistant helping with web fuzzing for a bug bounty. The target URL is: {url}.\n"
        f"Technologies detected on the target: {tech_detected_str}.\n"
        f"Based on the detected technologies and common file extensions seen in web applications (e.g., .php, .aspx, .jsp, .html, .bak), "
        f"suggest the top {max_extensions} file extensions that are most likely relevant for fuzzing this target.\n"
        f"Consider how the detected technologies might influence the types of file extensions that are more likely to be in use.\n"
        f"Please respond with only a raw JSON array in the following format: [\"php\", \"bak\", \"html\"]."
    )

    body = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

    try:
        response = requests.post(endpoint, headers=headers, json=body)
        if response.status_code != 200:
            print(f"[-] Gemini API error: {response.status_code} - {response.text}")
            return []

        result = response.json()
        text_output = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

        try:
            # Remove unwanted characters and parse extensions
            cleaned_output = re.sub(r'```json\n|\n```|\s+', '', text_output.strip())
            extensions = json.loads(cleaned_output)

            if isinstance(extensions, list):
                # Clean extensions and return them
                return [ext.strip(".").strip() for ext in extensions][:max_extensions]
        except json.JSONDecodeError:
            # Fallback: try parsing comma-separated list if JSON fails
            extensions = [x.strip().strip(".") for x in text_output.strip().split(",")]
            if extensions:
                return extensions[:max_extensions]

        print("[-] Could not parse extensions properly.")
        return []

    except Exception as e:
        print(f"[-] Exception while calling Gemini API: {e}")
        return []

# Function to run httpx and detect technologies
def detect_technologies(url):
    print(f"[*] Detecting technologies for {url} using httpx...")
    
    # Debug: Print the command being run
    command = ['httpx', '-u', url, '-tech-detect']
    print(f"Running command: {' '.join(command)}")
    
    result = subprocess.run(command, capture_output=True, text=True)
    
    # Debugging: Print raw stdout and stderr from the httpx command
    print(f"Raw output:\n{result.stdout}")
    print(f"Raw error (if any):\n{result.stderr}")
    
    if result.returncode != 0:
        print(f"[-] Error running httpx: {result.stderr}")
        return []

    tech_detected = []
    # Now we'll parse the output properly by looking for the URL and the technologies in brackets
    for line in result.stdout.splitlines():
        if line.startswith(url):
            # Extract technologies from the line
            tech_detected = re.findall(r"\[([^\]]+)\]", line)
            if tech_detected:
                # Remove whitespace and split by commas
                tech_detected = tech_detected[0].split(',')
                tech_detected = [tech.strip() for tech in tech_detected]
                break

    return tech_detected

# Main execution function
def main():
    parser = argparse.ArgumentParser(description="Fuzz with Gemini-assisted extension discovery")
    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ keyword")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
    parser.add_argument("--max-extensions", type=int, default=5, help="Max number of extensions to use")
    args = parser.parse_args()

    url = args.url
    wordlist = args.wordlist

    if "FUZZ" not in url:
        print("[-] Warning: FUZZ keyword is not in the URL. Extension fuzzing won't work.")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[-] Gemini API key not found. Set it as GEMINI_API_KEY env variable.")
        sys.exit(1)

    headers = {"Content-Type": "application/json"}

    try:
        # Step 1: Detect technologies using httpx
        tech_detected = detect_technologies(url)
        
        if not tech_detected:
            print("[-] No technologies detected by httpx.")
            tech_detected = "None"
        else:
            print(f"[+] Detected technologies: {tech_detected}")

        # Step 2: Ask Gemini for suggested extensions
        print("[*] Asking Gemini for suggested extensions...")
        extensions = get_ai_extensions(url, headers, api_key, ", ".join(tech_detected), args.max_extensions)

        if not extensions:
            print("[-] No extensions suggested. Proceeding without -e flag.")
            extensions_flag = ""
        else:
            print(f"[+] Gemini Suggested Extensions: {extensions}")
            # Ensure that the extensions have a dot at the beginning
            extensions_with_dot = [f".{ext}" for ext in extensions]
            extensions_flag = ",".join(extensions_with_dot)

        # Step 3: Run ffuf with the extensions if available
        ffuf_cmd = ["ffuf", "-u", url, "-w", wordlist, "-c"]

        if extensions_flag:
            ffuf_cmd += ["-e", extensions_flag]

        print("[+] Running ffuf with command:", " ".join(ffuf_cmd))
        subprocess.run(ffuf_cmd)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
