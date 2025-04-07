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
    total = 0

    all_results = {}

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
        all_results[file] = result

        if ([x for x in result.values() if x]):
            total += 1

    print("Result: ")
    print(f"{total}/{len(files)} ({total / len(files) * 100}%)")
    print("")

    json_data = {}

    with open("stats.json", "r+") as file:
        json_data = json.load(file)

    print(
        f"Currently: {len(json_data["interesting"])} interesing, {len(json_data["common"])} common")

    with open("stats.json", "r+") as file:
        file.truncate(0)
        try:
            for sample in all_results.keys():

                if (sample in json_data["complete"]):
                    continue

                if (not len(all_results[sample]["urls"])):
                    json_data["complete"].append(sample)
                    continue

                print(all_results[sample])

                query = input("Interesting? (Y/N)")

                urls = set(all_results[sample]["urls"])
                interesting = set(json_data["interesting"])
                common = set(json_data["common"])

                if (query.lower() == "y"):
                    unique = urls - interesting
                    json_data["interesting"] += list(unique)
                else:
                    unique = urls - common
                    json_data["common"] += list(unique)

                json_data["complete"].append(sample)

            interesting = set(json_data["interesting"])
            common = set(json_data["common"])

            new_interesting = interesting - common
            json_data["interesting"] = list(new_interesting)

        finally:
            json.dump(json_data, file)


if __name__ == "__main__":
    main()
