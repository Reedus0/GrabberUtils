import os

from dotenv import load_dotenv
from Grabber.logs.logger import initLogging

from Grabber.db.db import DB

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.vx import VXDownloader


def download_sample(hash):
    abuse = AbuseDownloader(os.environ["ABUSE_API_KEY"])
    yarify = YarifyDownloader(os.environ["ABUSE_API_KEY"])
    vx = VXDownloader(os.environ["VX_API_KEY"])

    downloaders = [abuse, yarify, vx]

    for downloader in downloaders:
        downloader.download(hash)
        result = downloader.getResult()
        if (result):
            with open(os.environ["SAMPLE_PATH"] + "/" + hash, "wb") as sample:
                sample.write(result)
                sample.close()
            break


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    while (1):
        mode = input("Hash/Query (H/Q): ")
        if (mode.lower() == "h"):
            hash = input("Hash: ")
            download_sample(hash)
        elif (mode.lower() == "q"):
            db = DB(
                os.environ["DB_HOST"],
                os.environ["DB_PORT"],
                os.environ["DB_USER"],
                os.environ["DB_PASSWORD"],
                os.environ["DB_DATABASE"],
            )

            sql = input("Query: ")

            samples = db.querySamples(sql)
            print(samples)
            download = input("Download? (Y/N): ")

            if (download.lower() == "y"):
                for sample in samples:
                    download_sample(sample)


if __name__ == "__main__":
    main()
