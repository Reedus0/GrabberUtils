rule win32_dotnet_loader {
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET loader malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "d8848c4399130b94784433ee04c41e26"
        yarahub_uuid = "a356dfcb-eee9-4d59-b72b-9262ea903045"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "3"
    strings:
        $re_0 = /https?:\/\// wide
        $string_1 = "HttpClient"
        $string_2 = "GetByteArrayAsync"
        $string_3 = "GetAsync"
    condition:
        uint16(0) == 0x5A4D and $re_0 and 2 of ($string_*)
}