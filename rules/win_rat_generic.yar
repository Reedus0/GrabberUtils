rule win_rat_generic {
    meta:
        author = "Reedus0"
        description = "Rule for detecting generic RAT malware"
        date = "2024-04-14"
        yarahub_reference_md5 = "a943bea8997dec969ba9cff3286ef6e2"
        yarahub_uuid = "6447ce42-5626-4e62-813e-05719c45e014"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "3"
    strings:
        $rat = "RAT" ascii wide
        $runas = "runas" ascii wide
        $shell = "shell\\open\\command" ascii wide
        $run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $services = "SYSTEM\\CurrentControlSet\\Services" ascii wide
        $winsta0 = "winsta0" ascii wide
        $cmd_exe = "cmd.exe /c" ascii wide
        $cmd = "cmd /c" ascii wide
        $shell_execute = "ShellExecute" ascii
        $echo = "@echo off" ascii wide 
    condition:
        uint16(0) == 0x5A4D and (($rat and 2 of them) or 4 of them)
}