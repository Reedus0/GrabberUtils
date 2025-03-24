rule win32_vidar {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Vidar malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "4c6d805c1ce9b7ba6071ebd649c9557e"
        yarahub_uuid = "da199571-fcee-4ef7-9b3f-827a3100b36a"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "passwords.txt"
        $string_1 = "build_id"
        $string_2 = "token"
        $string_3 = "sqlite3.dll"
        $string_4 = "task_id"
        $string_5 = "^userContextId=4294967295"
        $string_6 = "/c timeout /t 10 & del /f /q"
        $string_7 = "iex(New-Object Net.WebClient).DownloadString"
    condition:
        uint16(0) == 0x5A4D and 5 of them
}