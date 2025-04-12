import os

from dotenv import load_dotenv

from mimics.SmokeLoader import SmokeLoaderMimic
from mimics.PureCrypterLoader import PureCrypterLoaderMimic


from Grabber.logs.logger import initLogging


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    # config = {
    #     "c2": "http://varmisende.com/upload/",
    #     "botnet_id": "pub5",
    #     "rc4_encrypt_key": 992142656,
    #     "rc4_decrypt_key": 2796787680
    # }

    config = {'url': 'http://161.248.239.119/ADOLF/Tympfcnhbde.mp3', 'key': '', 'iv': '', 'algorithm': 'RC2'}

    mimic = SmokeLoaderMimic(config, os.environ["SAMPLE_PATH"])
    if (mimic.validateConfig()):
        mimic.run()


if __name__ == "__main__":
    main()
