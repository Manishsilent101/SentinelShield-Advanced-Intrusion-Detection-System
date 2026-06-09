from flask import Flask, render_template, request
from detector import detect_attack
from logger import save_log

app = Flask(__name__)

sql_count = 0
xss_count = 0
dir_count = 0
lfi_count = 0
command_count = 0
brute_force_count = 0
request_count = 0


def get_recent_logs():
    try:
        with open("logs/attacks.log", "r") as file:
            logs = file.readlines()

        return logs[-5:]

    except:
        return []


@app.route("/", methods=["GET", "POST"])
def home():

    global sql_count
    global xss_count
    global dir_count
    global lfi_count
    global command_count
    global brute_force_count
    global request_count

    result = ""

    if request.method == "POST":

        request_count += 1

        request_data = request.form["request_data"]

        attack = detect_attack(request_data)

        if request_count == 6:
            attack = "Brute Force"
            brute_force_count += 1

        elif attack == "SQL Injection":
            sql_count += 1

        elif attack == "XSS":
            xss_count += 1

        elif attack == "Directory Traversal":
            dir_count += 1

        elif attack == "LFI":
            lfi_count += 1

        elif attack == "Command Injection":
            command_count += 1

        if attack != "Normal Request":

            ip_address = request.remote_addr

            save_log(
                ip_address,
                attack,
                request_data
            )

            result = f"""
<h2>Attack Type: {attack}</h2>
<h2 style='color:red;'>Status: BLOCKED</h2>
"""

        else:

            result = f"""
<h2>Attack Type: {attack}</h2>
<h2 style='color:lime;'>Status: ALLOWED</h2>
"""

    recent_logs = get_recent_logs()

    total_attacks = (
        sql_count +
        xss_count +
        dir_count +
        lfi_count +
        command_count +
        brute_force_count
    )

    attack_stats = {
        "SQL Injection": sql_count,
        "XSS": xss_count,
        "Directory Traversal": dir_count,
        "LFI": lfi_count,
        "Command Injection": command_count,
        "Brute Force": brute_force_count
    }

    most_common_attack = max(
        attack_stats,
        key=attack_stats.get
    )

    return render_template(
        "index.html",
        result=result,
        sql_count=sql_count,
        xss_count=xss_count,
        dir_count=dir_count,
        lfi_count=lfi_count,
        command_count=command_count,
        brute_force_count=brute_force_count,
        recent_logs=recent_logs,
        total_attacks=total_attacks,
        most_common_attack=most_common_attack
    )


if __name__ == "__main__":
    app.run(debug=True)