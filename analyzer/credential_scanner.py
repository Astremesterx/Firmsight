import re


def scan_credentials(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    text = data.decode("latin-1", errors="ignore")

    patterns = {
        "password": r"(?i)password\s*[:=]\s*[^\s,;]+",
        "username": r"(?i)username\s*[:=]\s*[^\s,;]+",
        "API key": r"(?i)api[_-]?key\s*[:=]\s*[^\s,;]+",
        "secret": r"(?i)secret\s*[:=]\s*[^\s,;]+",
    }

    found = False

    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            print(f"Potential {label} found at offset {match.start()}")
            found = True

    if not found:
        print("No potential hardcoded credentials detected.")


if __name__ == "__main__":
    print("FirmSight Credential Scanner")
