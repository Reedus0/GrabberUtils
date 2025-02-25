import os

from dotenv import load_dotenv

from mimics.SmokeLoader import SmokeLoaderMimic

from Grabber.logs.logger import initLogging
from dotenv import load_dotenv


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    config = {
        # "c2": "http://d-s-p.ru/tmp/index.php",
        # "c2": "http://127.0.0.1",
        "c2": "http://bahninfo.at/upload/",
        "botnet_id": "pub5",
        "rc4_encrypt_key": 992142656,
        "rc4_decrypt_key": 2796787680
    }

    mimic = SmokeLoaderMimic(config, os.environ["SAMPLE_PATH"])
    if (mimic.validateConfig()):
        mimic.run()


if __name__ == "__main__":
    main()
