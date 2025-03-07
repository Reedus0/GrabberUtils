import re

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def XORAgentTesla():

    def decrypt(sample: Sample, regex_result: re.Match):
        pass

    extract = Regex(
        "sample",
        "custom",
        (
            b"(.)"
        ),
        decrypt)

    return Extractor("XORAgentTesla", [extract])


def AgentTesla():

    def extract(sample: Sample, regex_result: re.Match):
        pass

    telegram = Regex(
        "telegram",
        "custom",
        (
            b"(.)"
        ),
        extract)

    return Extractor("AgentTesla", [telegram])
