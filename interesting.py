import os
import json

from Grabber.config.sample import Sample
from Grabber.config.processor import Processor
from Grabber.config.extractor import Extractor

from extractors.DotnetLoader import DotnetLoader

from Grabber.logs.logger import initLogging, log
from dotenv import load_dotenv


def main():
    load_dotenv()
    initLogging(10, os.environ["LOG_PATH"])

    files = []

    for (dirpath, dirnames, filenames) in os.walk(os.environ["SAMPLE_PATH"] + "/"):
        files.extend(filenames)
        break

    workers = [DotnetLoader()]

    log(10, "Running extractor...")

    json_data = {}

    with open("stats.json", "r+") as file:
        json_data = json.load(file)

    print(
        f"Currently: {len(json_data["interesting"])} interesing, {len(json_data["common"])} common")

    with open("stats.json", "r+") as out_file:
        out_file.truncate(0)
        try:

            for file in files:

                if (file in json_data["complete"]):
                    continue

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

                if (not len(result["urls"])):
                    json_data["complete"].append(file)
                    continue

                for url in result["urls"]:
                    if (url in json_data["interesting"].keys()):
                        json_data["interesting"][url] += 1
                        continue

                    if (url in json_data["common"].keys()):
                        json_data["common"][url] += 1
                        continue

                    print(url)
                    query = input("Interesting? (Y/N): ")

                    if (query.lower() == "y"):
                        json_data["interesting"][url] = 1
                    else:
                        json_data["common"][url] = 1

                json_data["complete"].append(file)

        finally:
            json.dump(json_data, out_file)

        # WITH tb AS (SELECT id, sha256_hash, row_number() OVER (ORDER BY id) as row FROM sample WHERE malware_family = 'win32_dotnet_loader') SELECT id, sha256_hash FROM tb WHERE tb.row BETWEEN 1000 AND 2000;


if __name__ == "__main__":
    main()