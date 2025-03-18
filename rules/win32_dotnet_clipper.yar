rule win32_dotnet_clipper {
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET clipper malware"
        date = "2024-03-18"
        yarahub_reference_md5 = "72d0bd62f139ca8c0c6ca24d29e7a5ff"
        yarahub_uuid = "a62fd28e-3064-488d-8178-8c3c278e283b"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "374DE290-123F-4565-9164-39C4925E467B" wide
        $string_1 = "crash" wide
        $string_2 = "bustaville" wide
        $string_3 = "softwaresetupfile" wide
        $string_4 = "predicts" wide
        $string_5 = "launcher" wide
        $string_6 = "1xbet" wide
    condition:
        uint16(0) == 0x5A4D and 5 of them
}