import os

from dotenv import load_dotenv

from mimics.SmokeLoader import SmokeLoaderMimic
from mimics.PureCrypterLoader import PureCrypterLoaderMimic


from Grabber.logs.logger import initLogging


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    # config = {
    #     "c2": "http://prolinice.ga/index.php",
    #     "botnet_id": "",
    #     "rc4_encrypt_key": 313803588,
    #     "rc4_decrypt_key": 2616091366
    # }

    config = {'url': 'http://196.251.83.222/win32/panel/uploads/Dpycme.pdf', 'key': 'T2XHruGCfIvo3Nf8GSxx6g==', 'iv': 'ugvHoHdatJQ=', 'algorithm': 'RC2'}

    mimic = PureCrypterLoaderMimic(config, os.environ["SAMPLE_PATH"])
    if (mimic.validateConfig()):
        mimic.run()


if __name__ == "__main__":
    main()
