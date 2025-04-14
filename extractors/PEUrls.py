import re

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def PEUrls():

    def extract(sample: Sample, regex_result: re.Match):
        result = []

        regex_ascii = b"(https?://[A-Za-z0-9.:/?#=]+)"
        regex_utf = b"(h\x00t\x00t\x00p\x00s?\x00?:\x00/\x00/\x00[A-Za-z0-9.:/\x00?#=]+)\x00\x00"

        match = re.findall(regex_ascii, sample.getData())
        match += re.findall(regex_utf, sample.getData())

        for url in match:
            url = url.decode()
            splited = url.split("http")[1:]
            for link in splited:
                result.append("http" + link)

        return result

    urls = Regex(
        "urls",
        "custom",
        (
            b"(.)"
        ),
        extract)

    return Extractor("PEUrls", [urls])
