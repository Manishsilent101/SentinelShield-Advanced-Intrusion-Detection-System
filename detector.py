def detect_attack(data):

    data = data.lower()

   

    if "or 1=1" in data:
        return "SQL Injection"

    elif "<script>" in data:
        return "XSS"

    elif "../" in data:
        return "Directory Traversal"

    elif "/etc/passwd" in data or "boot.ini" in data:
        return "LFI"

    elif (
        "whoami" in data or
        "&&" in data or
        ";" in data or
        "|" in data or
        "cmd" in data or
        "dir" in data or
        "ls" in data or
        "pwd" in data or
        "cat " in data or
        "ping " in data or
        "ipconfig" in data or
        "netstat" in data
    ):
      
        return "Command Injection"

    else:
        return "Normal Request"