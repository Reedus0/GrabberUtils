import re

from Grabber.config.sample import Sample
from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex


def njrat():
    def extract(sample: Sample, regex_result: re.Match):
        data = sample.getData()
        nullmatch: re.Match[bytes] | None = re.search(
            b'\x00\x00', data[regex_result.start():])

        if (not nullmatch):
            return

        unicode_offset = nullmatch.start() + regex_result.start()
        unicode_data = data[unicode_offset:300+unicode_offset]

        config = []
        for chars in unicode_data:
            char = chars.to_bytes(1, byteorder="little")

            if char > b'\x00' and char < b'\x2E' and char != b'1B' and char != b'27':
                config.append("&")
            elif char < b'\x7F' and char > b'\x20':
                try:
                    config.append(char.decode("utf-8"))
                except UnicodeDecodeError:
                    pass

        config_string = ''.join(config)
        splited_config = config_string.split("&")

        ip_regex = r"(\d{1,3}\.){3}\d{1,3}"

        for param in splited_config:
            match = re.search(ip_regex, param)
            if (match):
                return match[0]

        address_regex = r"([\w-]+\.){1,}[^exe][a-zA-Z]{2,5}"

        for param in splited_config:
            match = re.search(address_regex, param)
            if (match):
                return match[0]

        return ""

    config = Regex(
        "c2",
        "custom",
        (
            b"\\x47\\x65\\x74\\x57\\x69\\x6E\\x64\\x6F\\x77\\x54\\x65\\x78\\x74(.*)\\x00\\x00"
        ),
        extract)

    return Extractor("njrat", [config])
