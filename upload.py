import os
import requests

from dotenv import load_dotenv
from Grabber.logs.logger import initLogging, log


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    headers = {
        "Auth-Key": os.environ["ABUSE_API_KEY"]
    }
    rules = os.listdir(os.environ["RULES_PATH"])

    for rule in rules:
        with open(os.environ["RULES_PATH"] + "/" + rule, "r") as file:

            data = {
                "yara_file": file
            }

            response = requests.post("https://yaraify-api.abuse.ch/api/v1/",
                                     files=data, verify=True, headers=headers)
            response_json = response.json()

            if (response_json["query_status"] == "ok"):
                log(10, f"Uploaded rule {rule}")
            else:
                log(20, f"Failed to upload rule {rule}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
