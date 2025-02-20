import os
from dotenv import load_dotenv

from Grabber.collectors.abuse import AbuseCollector
from Grabber.collectors.yarify import YarifyCollector
from Grabber.collectors.ha import HybridAnalysisCollector

from Grabber.scanners.virustotal import VirusTotalScanner
from Grabber.db.db import DB

from Grabber.logs.logger import log, initLogging


def main():

    load_dotenv()
    initLogging(10, os.environ["LOG_PATH"])

    db = DB(
        os.environ["DB_HOST"],
        os.environ["DB_PORT"],
        os.environ["DB_USER"],
        os.environ["DB_PASSWORD"],
        os.environ["DB_DATABASE"],
    )

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

    log(10, "Deleting existing samples...")

    filtered_samples = []

    for sample in raw_samples:
        if (not db.sampleExists(sample)):
            filtered_samples.append(sample)

    log(10, "Successfully deleted existing samples!")

    scanned_samples = []
    scanners = [VirusTotalScanner(os.environ["VIRUSTOTAL_API_LEY"])]

    log(10, "Scanning samples...")

    for scanner in scanners:
        scanner.scan(filtered_samples)
        scanned_samples += scanner.getResult()

    log(10, "Successfully scanned " + str(len(scanned_samples)) + " samples!")

    log(10, "Initiatiating DB connection...")

    log(10, "Adding samples to DB...")

    for sample in scanned_samples:
        db.addSample(sample)

    log(10, "Successfully added samples to DB!")


if __name__ == "__main__":
    main()
