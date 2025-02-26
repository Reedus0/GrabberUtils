import os

from dotenv import load_dotenv

from mimics.SmokeLoader import SmokeLoaderMimic

from Grabber.logs.logger import initLogging


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    config = {
        "c2": "http://prolinice.ga/index.php",
        "botnet_id": "",
        "rc4_encrypt_key": 313803588,
        "rc4_decrypt_key": 2616091366
    }

    mimic = SmokeLoaderMimic(config, os.environ["SAMPLE_PATH"])
    if (mimic.validateConfig()):
        mimic.run()


if __name__ == "__main__":
    main()
