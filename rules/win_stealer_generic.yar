rule win_stealer_generic {
    meta:
        author = "Reedus0"
        description = "Rule for detecting generic stealer malware"
        date = "2024-03-24"
        yarahub_reference_md5 = "f7a42a34500d995225266e7a6584099e"
        yarahub_uuid = "58644591-f53d-495e-a5ba-39f7d499d3d9"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "5"
    strings:
        $stealer = "stealer" ascii wide nocase
        $tdata = "tdata" ascii wide
        $wallet = "wallet" ascii wide
        $chrome = "chrome" ascii wide
        $firefox = "firefox" ascii wide
        $token = "token" ascii wide
        $runas = "runas" ascii wide
        $steam = "SOFTWARE\\Valve\\Steam" ascii wide
        $shell = "shell\\open\\command" ascii wide
        $discord = "discord\\Local Storage\\leveldb\\" ascii wide
        $run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($stealer or 4 of them) and filesize < 10MB
}