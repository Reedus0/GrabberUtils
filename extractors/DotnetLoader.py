import re

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def DotnetLoader():
    def extract(sample: Sample, regex_result: re.Match):
        result = []

        if (not regex_result):
            return ""

        extract_result = regex_result[1]

        for i in range(0, len(extract_result) - 1, 2):
            result.append(chr(extract_result[i]))

        return "".join(result)

    url = Regex(
        "url",
        "custom",
        (
            b"(h\x00t\x00t\x00p\x00s?\x00?:\x00\/\x00\/(\x00.)+\x00\x00)"
        ),
        extract)

    key = Regex(
        "key",
        "cli_offset",
        (
            b"\\x38.{3}."
            b"\\x72(.{3})\\x70"
            b"\\x28.{3}\\x0A"
            b"\\x13[^\\x05]"
        ))

    iv = Regex(
        "iv",
        "cli_offset",
        (
            b"\\x38.{3}."
            b"\\x72(.{3})\\x70"
            b"\\x28.{3}\\x0A"
            b"\\x13\\x05"
        ))

    return Extractor("DotnetLoader", [url, key, iv])
