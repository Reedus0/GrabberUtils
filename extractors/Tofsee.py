import re
import string

from Grabber.config.extractor import Extractor
from Grabber.config.regex import Regex
from Grabber.config.sample import Sample


def Tofsee():

    def decrypt(string):
        result = []
        acc = 228
        i = 1
        j = 0
        count = len(string)

        while (count):
            next_char = chr(acc ^ string[j])

            if (next_char == "\x00"):
                break

            result.append(next_char)

            v8 = 200 + i
            i = -i
            acc += v8
            acc = acc & 255
            count = count - 1
            j += 1

        return "".join(result)

    def get_c2(sample: Sample, regex_result: re.Match):
        extract_result = regex_result[1]

        offset = sample.getPhysicalAddress(
            int.from_bytes(extract_result, "little"))

        c2 = sample.readBytesString(offset)

        if (chr(c2[0]) not in string.printable):
            return decrypt(c2)

        return sample.readASCIIString(offset)

    c2 = Regex(
        "c2",
        "custom",
        (
            b"\\x57"
            b"\\x6A\\x02"
            b"\\xBE(.{4})"
        ),
        get_c2)

    return Extractor("Tofsee", [c2])
