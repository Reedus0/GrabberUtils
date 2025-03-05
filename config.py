import os

from Grabber.logs.logger import initLogging
from Grabber.config.sample import Sample

from extractors.LeprechaunVNC import LeprechaunVNC
from extractors.XWorm import XWorm
from extractors.YoungLotus import YoungLotus
from extractors.njrat import njrat
from extractors.DotnetLoader import DotnetLoader
from extractors.PureCrypterLoader import PureCrypterLoader

from dotenv import load_dotenv


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    extractors = [XWorm(), YoungLotus(), njrat(), LeprechaunVNC(), DotnetLoader(), PureCrypterLoader()]
    chosen_extractor = None

    for extractor in extractors:
        print(extractor.getName())

    extractor_name = input("Extractor: ")

    for extractor in extractors:
        if (extractor_name == extractor.getName()):
            chosen_extractor = extractor

    name = input("Name: ")

    sample = Sample(os.environ["SAMPLE_PATH"] + "/" + name)
    chosen_extractor.extract(sample)
    result = chosen_extractor.getResult()

    print(result)


if __name__ == "__main__":
    main()
