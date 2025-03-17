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


def yara_scan_samples(samples):
    scanned_samples = []

    scanner = YaraScanner(
        os.environ["RULES_PATH"], os.environ["SAMPLE_PATH"])

    for sample in samples:
        try:
            if (not sample["malware_family"]):
                download_sample(sample["sha256_hash"])
                scanned_samples.append(scanner.scan(sample))
            else:
                scanned_samples.append(sample)
        except Exception as e:
            log(20, "Error: " + e.message)
            scanned_samples.append(sample)

    return scanned_samples


def config_extract_samples(samples):
    scanned_samples = []

    config = {
        "win32_dotnet_loader": {"extractor": DotnetLoader},
        "win32_xworm": {"extractor": XWorm}
    }
    scanner = ConfigScanner(os.environ["SAMPLE_PATH"], config)

    for sample in samples:
        try:
            if (sample["malware_family"] in config.keys()):
                download_sample(sample["sha256_hash"])
                scanned_samples.append(scanner.scan(sample))
            else:
                scanned_samples.append(sample)

            try:
                os.remove(os.environ["SAMPLE_PATH"] +
                          "/" + sample["sha256_hash"])
            except FileNotFoundError:
                pass
        except Exception as e:
            log(20, "Error: " + e.message)
            scanned_samples.append(sample)

    return scanned_samples


def virustotal_scan_samples(samples):
    scanned_samples = []

    scanner = VirusTotalScanner(os.environ["VIRUSTOTAL_API_LEY"])

    for sample in samples:
        try:
            if (not sample["malware_family"]):
                scanned_samples.append(scanner.scan(sample))
            else:
                scanned_samples.append(sample)
        except Exception as e:
            log(20, "Error: " + e.message)
            scanned_samples.append(sample)

    return scanned_samples


def upload_samples(samples):
    log(10, "Initiatiating DB connection...")

    db = DB(
        os.environ["DB_HOST"],
        os.environ["DB_PORT"],
        os.environ["DB_USER"],
        os.environ["DB_PASSWORD"],
        os.environ["DB_DATABASE"],
    )

    log(10, "Uploading samples to DB...")

    for sample in samples:
        db.addSample(sample)

    log(10, "Successfully added samples to DB!")


def main():

    load_dotenv()
    initLogging(10, os.environ["LOG_PATH"])

    raw_samples = collect_samples()
    filtered_samples = delete_existing_samples(raw_samples)

    log(10, "Scanning " + str(len(filtered_samples)) + " samples...")

    scanned_samples = yara_scan_samples(filtered_samples)
    scanned_samples = config_extract_samples(scanned_samples)
    scanned_samples = virustotal_scan_samples(scanned_samples)

    log(10, "Successfully scanned " + str(len(scanned_samples)) + " samples!")

    upload_samples(scanned_samples)


if __name__ == "__main__":
    main()
