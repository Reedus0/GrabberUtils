import os

from Grabber.config.sample import Sample

from extractors.LeprechaunVNC import LeprechaunVNC
from extractors.XWorm import XWorm
from extractors.SmokeLoader import SmokeLoader, ExtractSmokeLoader
from extractors.njrat import njrat
from extractors.PureCrypterLoader import PureCrypterLoader
from extractors.DotnetLoader import DotnetLoader
from extractors.YoungLotus import YoungLotus
from extractors.AgentTesla import AgentTesla, XORAgentTesla

from Grabber.logs.logger import initLogging, log
from dotenv import load_dotenv

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
    initLogging(10, os.environ["LOG_PATH"])

    new_samples = input("New samples? (Y/N): ")

    if (new_samples.lower() == "y"):
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
            for i in range(len(samples)):
                sample = samples[i]
                download_sample(sample)
                log(10, f"Sample {i + 1}/{len(samples)}")

    files = []
    for (dirpath, dirnames, filenames) in os.walk(os.environ["SAMPLE_PATH"] + "/"):
        files.extend(filenames)
        break

    preprocessor = XORAgentTesla()
    extractor = AgentTesla()

    log(10, "Running extractor...")
    total = 0

    for file in files:
        sample = Sample(os.environ["SAMPLE_PATH"] + "/" + file)
        log(10, "Sample: " + file)

        if (preprocessor):
            preprocessor.extract(sample)
            result = preprocessor.getResult()
            sample = result["sample"]

        if (not sample):
            continue

        extractor.extract(sample)
        result = extractor.getResult()

        print(result)

        if ([x for x in result.values() if x]):
            total += 1

    print("Result: ")
    print(f"{total}/{len(files)} ({total / len(files) * 100}%)")
    print("")

if __name__ == "__main__":
    main()
