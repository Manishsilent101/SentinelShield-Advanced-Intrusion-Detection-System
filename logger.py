from datetime import datetime

def save_log(ip_address, attack_type, request_data):

    with open("logs/attacks.log", "a") as file:

        file.write(
            f"{datetime.now()} |{ip_address}  | {attack_type} | {request_data}\n"
        )