import os

from dotenv import load_dotenv

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.ha import HybridAnalysisDownloader

from Grabber.sandbox.ha import HybridAnalysisSandbox

from Grabber.logs.logger import initLogging


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


def sandbox_sample(hash):
    ha = HybridAnalysisSandbox(os.environ["HYBRID_ANALYSIS_API_KEY"])
    id = ha.sendToSendbox(open(os.environ["SAMPLE_PATH"] + "/" + hash, "rb"))
    ha.waitForAnalysis(id)
    print(ha.getResult())


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    while (1):
        hash = input("Hash: ")
        download_sample(hash)

        scan = input("Scan? (Y/N): ")

        if (scan.lower() == "y"):
            sandbox_sample(hash)


if __name__ == "__main__":
    main()
