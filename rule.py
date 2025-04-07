import os

from Grabber.config.sample import Sample
from Grabber.config.processor import Processor
from Grabber.config.extractor import Extractor

from extractors.LeprechaunVNC import LeprechaunVNC
from extractors.XWorm import XWorm
from extractors.SmokeLoader import SmokeLoader, ExtractSmokeLoader, SmokeLoaderId
from extractors.njRAT import njRAT
from extractors.PureCrypterLoader import PureCrypterLoader
from extractors.DotnetLoader import DotnetLoader
from extractors.YoungLotus import YoungLotus
from extractors.AgentTesla import AgentTesla, XORAgentTesla
from extractors.Tofsee import Tofsee
from extractors.MeduzaStealer import MeduzaStealer

from Grabber.logs.logger import initLogging, log
from dotenv import load_dotenv

from Grabber.db.db import DB

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.vx import VXDownloader


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


def main():
    load_dotenv()
    initLogging(10, os.environ["LOG_PATH"])

    new_samples = input("New samples? (Y/N/F): ")

    if (new_samples.lower() == "y" or new_samples.lower() == "f"):
        db = DB(
            os.environ["DB_HOST"],
            os.environ["DB_PORT"],
            os.environ["DB_USER"],
            os.environ["DB_PASSWORD"],
            os.environ["DB_DATABASE"],
        )

        sql = ""

        if (new_samples.lower() == "f"):
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

    files = []

    for (dirpath, dirnames, filenames) in os.walk(os.environ["SAMPLE_PATH"] + "/"):
        files.extend(filenames)
        break

    # workers = [SmokeLoaderId(), ExtractSmokeLoader(os.environ["LIB_PATH"]), SmokeLoader()]
    workers = [DotnetLoader()]

    log(10, "Running extractor...")
    total = 0

    for file in files:
        sample = Sample(os.environ["SAMPLE_PATH"] + "/" + file)
        log(10, "Sample: " + file)

        result = {}

        for worker in workers:
            if (isinstance(worker, Processor)):
                worker.processSample(sample)
                sample = worker.getResult()
            if (isinstance(worker, Extractor)):
                worker.extract(sample)
                result = {**result, **worker.getResult()}

        print(result)

        if ([x for x in result.values() if x]):
            total += 1

    print("Result: ")
    print(f"{total}/{len(files)} ({total / len(files) * 100}%)")
    print("")


if __name__ == "__main__":
    main()
