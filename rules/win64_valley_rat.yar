rule win64_valley_rat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting ValleyRAT malware"
        date = "2024-04-14"
        yarahub_reference_md5 = "08778fc09ac8ff3af6f21a0e7a27fafc"
        yarahub_uuid = "ff16a44f-f146-42ba-81aa-9f837f453f31"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.valley_rat"
        version = "3"
    strings:
        $string_0 = "CKernelManager"
        $string_1 = "CUdpSocket"
        $string_2 = "CManager"
        $string_3 = "CTcpSocket"
        $string_4 = "USER32.DLL" wide
        $string_5 = "winsta0"
    condition:
        uint16(0) == 0x5A4D and 5 of them
}