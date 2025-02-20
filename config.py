import os

from Grabber.logs.logger import initLogging
from Grabber.config.sample import Sample

from extractors.LeprechaunVNC import LeprechaunVNC
from extractors.ValleyRAT64 import ValleyRAT64
from extractors.MysticStealer import MysticStealer
from extractors.XWorm import XWorm
from extractors.YoungLotus import YoungLotus
from extractors.njrat import njrat

from dotenv import load_dotenv


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    samples = []
    for (dirpath, dirnames, filenames) in os.walk(os.environ["SAMPLE_PATH"]):
        samples.extend(filenames)
        break

    extractor = MysticStealer()
    total = 0

    for sample in samples:
        sample = Sample(os.environ["SAMPLE_PATH"] + "/" + sample)
        extractor.extract(sample)
        result = extractor.getResult()

        print(result)

        if (len(result.keys())):
            total += 1

    print("Result: ")
    print(f"{total}/{len(samples)} ({total / len(samples) * 100}%)")
    print("")


if __name__ == "__main__":
    main()
