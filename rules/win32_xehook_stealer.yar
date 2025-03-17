import "pe"

rule win32_xehook_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting XehookStealer malware"
        date = "2024-02-26"
        yarahub_reference_md5 = "3e879910e01a8e6b4576a0d50e7ca62d"
        yarahub_uuid = "13724b9e-7d30-40c4-80f8-3bb1b0e20efb"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.xehook"
        version = "1"
    strings:
        $string_0 = "getjson.php?id=" wide
        $string_1 = "index.html" wide
        $string_2 = "-Command \"Start-Process" wide
        $string_3 = "ping 127.0.0.1 -n 2 > nul" wide
        $string_4 = "UserInformation.txt"
        $string_5 = "{0}xh.php?id={1}&build={2}&passwords={3}&cookies={4}" wide
    condition:
        uint16(0) == 0x5A4D and (4 of them or $string_5)
}