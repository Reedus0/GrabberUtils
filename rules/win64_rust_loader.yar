rule win64_rust_loader {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Rust Loader"
        date = "2024-06-04"
        yarahub_reference_md5 = "e447d3b92a981234383564ec2b15d041"
        yarahub_uuid = "c1056ea3-c1a0-4ebd-879e-aa5f5b6462f7"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
       $string_0 = "/home/kali/.cargo"
       $string_1 = "USERNAME"
       $string_2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
       $string_3 = "ipconfig"
       $string_4 = "loader_version"
       $string_5 = "powershell.exe"
       $string_6 = "/report-status"
    condition:
        uint16(0) == 0x5A4D and 4 of them
}