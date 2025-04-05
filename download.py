import os

from dotenv import load_dotenv
from Grabber.logs.logger import initLogging

from Grabber.db.db import DB

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.vx import VXDownloader

from Grabber.logs.logger import log


def download_sample(hash):

    downloaders = [
        YarifyDownloader(os.environ["ABUSE_API_KEY"]),
        AbuseDownloader(os.environ["ABUSE_API_KEY"]),
        VXDownloader(os.environ["VX_API_KEY"])
    ]

    for downloader in downloaders:
        downloader.download(hash)
        result = downloader.getResult()
        if (result):
            with open(os.environ["SAMPLE_PATH"] + "/" + hash, "wb") as sample:
                sample.write(result)
                sample.close()
            break
    else:
        log(10, "Failed to download sample...")


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    while (1):
        mode = input("Hash/Query/Family (H/Q/F): ")
        if (mode.lower() == "h"):
            hash = input("Hash: ")
            download_sample(hash)
        elif (mode.lower() == "y" or mode.lower() == "f"):
            db = DB(
                os.environ["DB_HOST"],
                os.environ["DB_PORT"],
                os.environ["DB_USER"],
                os.environ["DB_PASSWORD"],
                os.environ["DB_DATABASE"],
            )

            sql = ""

            if (mode.lower() == "f"):
                sql = f"SELECT * FROM sample WHERE malware_family = '{input("Family: ")}' ORDER BY id DESC LIMIT 100;"
            else:
                sql = input("Query: ")

            samples = db.querySamples(sql)
            print(samples)
            download = input("Download? (Y/N): ")

            if (download.lower() == "y"):
                for i in range(len(samples)):
                    sample = samples[i]
                    download_sample(sample)
                    log(10, f"Sample {i + 1}/{len(samples)}")


if __name__ == "__main__":
    main()
