import requests
import webbrowser
import json
from datetime import datetime

print("=" * 20 + " OSINT BOT  " + "=" * 20)

# ---------------- INPUT HELPERS ---------------- #

def get_input(prompt, required=False):
    while True:
        value = input(prompt).strip()
        if value or not required:
            return value
        print("[!] This field is required.")

def yes_no(prompt):
    while True:
        choice = input(prompt + " (yes/no): ").strip().lower()
        if choice in ["yes", "no"]:
            return choice
        print("[!] Please enter 'yes' or 'no'.")

# ---------------- DATA COLLECTION ---------------- #

def recon():
    print("\n[+] Provide target details (leave blank if unknown)\n")

    target = {
        "name": get_input("Full name: "),
        "email": get_input("Email: "),
        "mobile": get_input("Mobile: "),
        "country": get_input("Country: "),
        "socials": {}
    }

    platforms = ["instagram", "facebook", "github", "twitter"]

    for platform in platforms:
        if yes_no(f"Do they have {platform}?") == "yes":
            username = input(f"Enter {platform} username: ").strip()
            target["socials"][platform] = username

    print("\n[+] Data Collected\n")
    return target

# ---------------- SOCIAL CHECK ---------------- #

def check_social_profiles(socials):
    print("\n[+] Checking public profiles...\n")

    base_urls = {
        "instagram": "https://www.instagram.com/{}",
        "github": "https://github.com/{}",
        "facebook": "https://www.facebook.com/{}",
        "twitter": "https://twitter.com/{}"
    }

    results = {}

    for platform, username in socials.items():
        url = base_urls.get(platform, "").format(username)

        try:
            r = requests.get(url, timeout=5)

            if r.status_code == 200:
                print(f"[+] FOUND: {platform} → {url}")
                results[platform] = {
                    "status": "found",
                    "url": url
                }
            else:
                print(f"[-] NOT FOUND: {platform}")
                results[platform] = {"status": "not_found"}

        except Exception as e:
            print(f"[!] ERROR: {platform}")
            results[platform] = {"status": "error"}

    return results

# ---------------- DORK GENERATOR ---------------- #

def generate_dorks(target):
    print("\n[+] Generating smart dorks...\n")

    dorks = {
        "identity": [],
        "documents": [],
        "credentials": [],
        "code_leaks": []
    }

    name = target.get("name")
    email = target.get("email")
    usernames = list(target.get("socials", {}).values())

    if name:
        dorks["identity"] += [
            f'"{name}" site:linkedin.com',
            f'"{name}" "resume" OR "cv"',
            f'"{name}" filetype:pdf'
        ]

    if email:
        dorks["credentials"] += [
            f'"{email}"',
            f'"{email}" "password"',
            f'"{email}" filetype:txt OR filetype:log'
        ]

    for user in usernames:
        dorks["code_leaks"] += [
            f'"{user}" site:github.com',
            f'"{user}" site:pastebin.com',
            f'"{user}" "leak" OR "dump"'
        ]

    return dorks

# ---------------- DORK HANDLING ---------------- #

def open_dorks(dorks):
    for queries in dorks.values():
        for q in queries:
            url = f"https://www.google.com/search?q={q}"
            webbrowser.open(url)

# ---------------- CORRELATION ENGINE ---------------- #

def calculate_score(target, social_results):
    print("\n[+] Calculating exposure score...\n")

    score = 0

    found = sum(1 for v in social_results.values() if v["status"] == "found")
    score += found * 15

    if target.get("email"):
        score += 20

    if target.get("name"):
        score += 10

    print(f"[+] Exposure Score: {score}/100")
    return score

# ---------------- REPORT GENERATION ---------------- #

def generate_report(target, social_results, dorks, score):
    report = {
        "timestamp": str(datetime.now()),
        "target": target,
        "social_results": social_results,
        "dorks": dorks,
        "exposure_score": score
    }

    filename = "report.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved: {filename}")

# ---------------- MAIN PIPELINE ---------------- #

def run():
    consent = input("Do you have authorization? (yes/no): ").lower()
    if consent != "yes":
        print("[-] Unauthorized use not allowed.")
        return

    target = recon()

    social_results = check_social_profiles(target["socials"])
    dorks = generate_dorks(target)

    if yes_no("Open dorks in browser?") == "yes":
        open_dorks(dorks)

    score = calculate_score(target, social_results)

    if yes_no("Save report to report.json?") == "yes":       # ← fix 2
        generate_report(target, social_results, dorks, score)

    print("\n[+] Scan Complete\n")

# ---------------- RUN ---------------- #

if __name__ == "__main__":
    run()