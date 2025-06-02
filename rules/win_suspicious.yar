rule win_suspicious {
    meta:
        author = "Reedus0"
        description = "Rule for detecting suspicious files"
        date = "2025-02-06"
        yarahub_reference_md5 = ""
        yarahub_uuid = ""
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "VirtualAlloc" fullword ascii
        $string_1 = "WriteProcessMemory" fullword ascii
        $string_2 = "CreateRemoteThread" fullword ascii
        $string_3 = "LoadLibraryA" fullword ascii
        $string_4 = "GetProcAddress" fullword 
        $string_5 = "WinExec" fullword ascii 
        $string_6 = "ShellExecuteA" fullword ascii  
        $string_7 = "InternetOpenA" fullword ascii 
        $string_8 = "InternetConnectA" fullword ascii  
        $string_9 = "URLDownloadToFileA" fullword ascii 

        $url = /https?:\/\/[a-z0-9\-\.]{4,256}\/[^\s"']{0,512}/

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            5 of ($string_*) or
            (2 of ($string_*) and $url)
        )
}