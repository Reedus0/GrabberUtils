import os

from Grabber.config.sample import Sample

from extractors.LeprechaunVNC import LeprechaunVNC
from extractors.XWorm import XWorm
from extractors.SmokeLoader import SmokeLoader, ExtractSmokeLoader
from extractors.njrat import njrat

from Grabber.logs.logger import initLogging, log
from dotenv import load_dotenv

from Grabber.db.db import DB

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.ha import HybridAnalysisDownloader


def download_sample(hash):
    abuse = AbuseDownloader(os.environ["ABUSE_API_KEY"])
    yarify = YarifyDownloader(os.environ["ABUSE_API_KEY"])
    ha = HybridAnalysisDownloader(os.environ["HYBRID_ANALYSIS_API_KEY"])

    downloaders = [abuse, yarify, ha]

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
    initLogging(20, os.environ["LOG_PATH"])

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

    last_stage_extractor = ExtractSmokeLoader(os.environ["LIB_PATH"])
    extractor = SmokeLoader()
    log(10, "Running extractor...")
    total = 0

    for file in files:
        sample = Sample(os.environ["SAMPLE_PATH"] + "/" + file)
        log(10, "Sample: " + file)

        last_stage_extractor.extract(sample)
        result = last_stage_extractor.getResult()
        sample, botned_id = result["extracted_sample"], result["botnet_id"]

        if (not sample):
            continue

        extractor.extract(sample)
        result = extractor.getResult()
        result["botnet_id"] = botned_id

        print(result)

        if (result["c2"] != ""):
            total += 1

    print("Result: ")
    print(f"{total}/{len(files)} ({total / len(files) * 100}%)")
    print("")

    # delete = input("Delete? (Y/N): ")

    # if (delete.lower() == "y"):

    #     log(10, "Removing samples...")

    #     for sample in files:
    #         os.remove(os.environ["SAMPLE_PATH"] + "/" + sample)

    #     log(10, "Successfully removed samples!")


if __name__ == "__main__":
    main()
