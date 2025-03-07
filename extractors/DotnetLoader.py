import re

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def DotnetLoader():
    def extract(sample: Sample, regex_result: re.Match):
        result = []
        regex = b"(h\x00t\x00t\x00p\x00s?\x00?:\x00/\x00/\x00[A-Za-z0-9.:/\x00?#=]+)\x00\x00"

        match = re.findall(regex, sample.getData())

        for url in match:
            result.append(url.decode().replace("\x00", ""))

        return result

    urls = Regex(
        "urls",
        "custom",
        (
            b"(.)"
        ),
        extract)

    return Extractor("DotnetLoader", [urls])
