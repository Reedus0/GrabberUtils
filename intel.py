import os
from dotenv import load_dotenv

from Grabber.collectors.abuse import AbuseCollector
from Grabber.collectors.yarify import YarifyCollector
from Grabber.collectors.ha import HybridAnalysisCollector

from Grabber.scanners.virustotal import VirusTotalScanner
from Grabber.scanners.yara import YaraScanner
from Grabber.scanners.config import ConfigScanner

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.vx import VXDownloader

from extractors.DotnetLoader import DotnetLoader
from extractors.XWorm import XWorm
from extractors.njRAT import njRAT
from extractors.YoungLotus import YoungLotus
from extractors.Tofsee import Tofsee

from Grabber.db.db import DB
from Grabber.logs.logger import log, initLogging


def download_sample(hash):
    if (os.path.exists(os.environ["SAMPLE_PATH"] + "/" + hash)):
        return

    downloaders = [
        AbuseDownloader(os.environ["ABUSE_API_KEY"]),
        YarifyDownloader(os.environ["ABUSE_API_KEY"]),
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


def collect_samples():
    raw_samples = []
    collectors = [
        YarifyCollector(os.environ["ABUSE_API_KEY"]),
        AbuseCollector(os.environ["ABUSE_API_KEY"]),
        HybridAnalysisCollector(os.environ["HYBRID_ANALYSIS_API_KEY"])
    ]

    log(10, "Collecting samples...")

    for collector in collectors:
        collector.collect()
        raw_samples += collector.getResult()

    log(10, "Successfully collected " + str(len(raw_samples)) + " samples!")

    return raw_samples


def delete_existing_samples(raw_samples):
    filtered_samples = []

    log(10, "Initiatiating DB connection...")

    db = DB(
        os.environ["DB_HOST"],
        os.environ["DB_PORT"],
        os.environ["DB_USER"],
        os.environ["DB_PASSWORD"],
        os.environ["DB_DATABASE"],
    )

    log(10, "Deleting existing samples...")

    for sample in raw_samples:
        if (not db.sampleExists(sample)):
            filtered_samples.append(sample)

    log(10, "Successfully deleted existing samples!")

    return filtered_samples


def yara_scan_sample(sample):

    result = sample

    scanner = YaraScanner(
        os.environ["RULES_PATH"], os.environ["SAMPLE_PATH"])

    try:
        if (not sample["malware_family"]):
            download_sample(sample["sha256_hash"])
            result = scanner.scan(sample)
    except Exception as e:
        log(20, str(e))

    return result


def config_extract_sample(sample):
    result = sample

    config = {
        "win32_dotnet_loader": [DotnetLoader()],
        "win32_xworm": [XWorm()],
        "win32_njRAT": [njRAT()],
        "win32_younglotus": [YoungLotus()],
        "win32_tofsee": [Tofsee()]
    }
    scanner = ConfigScanner(os.environ["SAMPLE_PATH"], config)

    try:
        if (sample["malware_family"] in config.keys()):
            download_sample(sample["sha256_hash"])
            result = scanner.scan(sample)
        try:
            os.remove(os.environ["SAMPLE_PATH"] +
                      "/" + sample["sha256_hash"])
        except FileNotFoundError:
            pass
    except Exception as e:
        log(20, str(e))

    return result


def virustotal_scan_sample(sample):

    result = sample

    scanner = VirusTotalScanner(os.environ["VIRUSTOTAL_API_LEY"])

    try:
        if (not sample["malware_family"]):
            result = scanner.scan(sample)

    except Exception as e:
        log(20, str(e))

    return result


def upload_sample(sample):
    log(10, "Initiatiating DB connection...")

    db = DB(
        os.environ["DB_HOST"],
        os.environ["DB_PORT"],
        os.environ["DB_USER"],
        os.environ["DB_PASSWORD"],
        os.environ["DB_DATABASE"],
    )

    log(10, "Uploading sample to DB...")

    db.addSample(sample)

    log(10, "Successfully added sample to DB!")


def main():

    load_dotenv()
    initLogging(10, os.environ["LOG_PATH"])

    raw_samples = collect_samples()
    filtered_samples = delete_existing_samples(raw_samples)

    log(10, "Scanning " + str(len(filtered_samples)) + " samples...")

    for sample in filtered_samples:

        sample = yara_scan_sample(sample)
        sample = config_extract_sample(sample)
        sample = virustotal_scan_sample(sample)

        upload_sample(sample)

    log(10, "Successfully scanned and uploaded " +
        str(len(filtered_samples)) + " samples!")


if __name__ == "__main__":
    main()
