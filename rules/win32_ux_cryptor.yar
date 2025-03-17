rule win32_ux_cryptor{
    meta:
        author = "Reedus0"
        description = "Rule for detecting UxCryptor malware"
        date = "2025-02-14"
        yarahub_reference_md5 = "00751893892e883fb14e10c23af87386"
        yarahub_uuid = "22f72606-2934-481d-adf8-a82916bff83d"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "Ooops! Your files are encrypted by the CryptoBytes hacker group!" wide
        $string_1 = "taskkill.exe /im Explorer.exe /f" wide
        $string_2 = "UX-Cryptor" wide
    condition:
        uint16(0) == 0x5A4D and 1 of them
}    