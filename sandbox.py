import os

from dotenv import load_dotenv

from Grabber.download.abuse import AbuseDownloader
from Grabber.download.yarify import YarifyDownloader
from Grabber.download.vx import VXDownloader

from Grabber.sandbox.ha import HybridAnalysisSandbox

from Grabber.logs.logger import initLogging, log


def download_sample(hash):

    downloaders = [
        YarifyDownloader(os.environ["ABUSE_API_KEY"]),
        AbuseDownloader(os.environ["ABUSE_API_KEY"]),
        VXDownloader(os.environ["VX_API_KEY"])
    ]

    try:
        for downloader in downloaders:
            downloader.download(hash)
            result = downloader.getResult()
            if (result):
                with open(os.environ["SAMPLE_PATH"] + "/" + hash, "wb") as sample:
                    sample.write(result)
                    sample.close()
                return True
        else:
            log(20, "Failed to download sample...")
            return False

    except Exception as e:
        log(20, str(e))
        return False


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
