rule win32_agent_tesla {
    meta:
        author = "Reedus0"
        description = "Rule for detecting AgentTesla malware"
        date = "2024-03-06"
        yarahub_reference_md5 = "a943bea8997dec969ba9cff3286ef6e2"
        yarahub_uuid = "af3452ab-ae29-470c-920f-7835dd3d845e"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.agent_tesla"
        version = "1"
    strings:
        $string_0 = { 06 91 06 61 20 ?? ?? ?? 00 61 D2 9C 06 17 58 0A 06 }
    condition:
        uint16(0) == 0x5A4D and all of them
}rule win32_discord_rat{
    meta:
        author = "Reedus0"
        description = "Rule for detecting Discord Rat malware"
        date = "2025-02-14"
        yarahub_reference_md5 = "086d48a6dea6258ec4a7b33c2e22bc59"
        yarahub_uuid = "fc32576c-355e-4044-bbdf-d689eb081b17"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "cc12258f-af24-4773-a8e3-45d365bcbde9" 
        $string_1 = "https://discord.com/api/v9/guilds/{0}/channels" wide
        $string_2 = "white_check_mark: New session opened" wide
        $string_3 = "Command executed!" wide
    condition:
        uint16(0) == 0x5A4D and ($string_0 or (3 of them))
}    rule win32_dotnet_form_obfuscate {
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET form obfuscate malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "24a04c8ba1c202b443c237c014c9721c"
        yarahub_uuid = "37809a30-6293-4dd0-8964-5e44bccd2fc2"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = { 28 ?? ?? ?? 0? [0-1] 16 [0-1] 28 ?? ?? ?? 0? [0-1] 73 ?? ?? ?? 06 28 ?? ?? ?? 0? }
    condition:
        uint16(0) == 0x5A4D and $string_0
}rule win32_dotnet_loader {
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
}import "pe"

rule win32_dotnet_obfuscate{
    meta:
        author = "Reedus0"
        description = "Rule for detecting .NET obfuscated malware"
        date = "2025-02-14"
        yarahub_reference_md5 = "9e7c6c00ffd9d6501586ff6e3a87ff47"
        yarahub_uuid = "ba2170cb-29c8-4645-996f-9b99425d89d6"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = { 2B 09 28 ?? ?? ?? ?? 14 16 9A 26 16 2D F9 28 13 12 00 06 00 7E 24 01 00 04 }
        $string_1 = { 73 ?? ?? ?? ?? 26 14 14 73 BC 00 00 06 28 72 00 00 06 }
        $string_2 = { 20 ?? ?? ?? ?? FE 0E 00 00 38 00 00 00 00 FE 0C 00 00 45 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and 1 of them
}    import "pe"

rule win32_lumma_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting LummaStealer malware"
        date = "2024-02-13"
        yarahub_reference_md5 = "9a675f29e768c405bf4705890fa9d2ba"
        yarahub_uuid = "46ec8e39-d171-43cc-bcc5-d77caafc723a"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.lumma"
        version = "2"
    strings:
        $string_0 = { 68 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 08 A3 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and #string_0 >= 5
}rule win32_mystic_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting Mystic Stealer malware"
        date = "2024-07-19"
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mystic_stealer"
        yarahub_reference_md5 = "1baba2d74f12915a3b89ecb883315008"
        yarahub_uuid = "288dfe16-1a9e-4d0f-8b2b-4ab80ffd15e9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.mystic_stealer"
        version = "1"
    strings:
        $create_mutex_a = { F1 6F EB D6 }
        $get_last_error = { 16 8A 16 1C }
        $create_file_w = { 7B D8 E4 F0 }
        $get_system_windows_directory_a = { 3D 08 FE D2 }
        $get_volume_information_a = { 59 ED 0D 98 }
        $snprintf = { B6 BF 4F 53 }
    condition:
        uint16(0) == 0x5A4D and all of them
}rule win32_njrat {
    meta:
        author = "Reedus0"
        description = "Rule for detecting njrat malware"
        date = "2025-02-01"
        yarahub_uuid = "882404f2-e440-4c51-8530-69a5d482eddd"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        yarahub_reference_md5 = "337cabfce35dc84645dbad617b58a418"
        version = "1"
    strings:
        $string_0 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide
        $string_1 = "cmd.exe /k ping 0 & del" wide
        $string_2 = "netsh firewall add allowedprogram" wide
        $string_3 = "/C choice /C Y /N /D Y /T 5 & Del" wide
        $string_4 = "schtasks /delete /tn" wide
        $string_5 = "SEE_MASK_NOZONECHECKS" wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}rule win32_redline_stealer {
    meta:
        author = "Reedus0"
        description = "Rule for detecting RedLine Stealer malware"
        date = "2024-03-03"
        yarahub_reference_md5 = "5b0363ac5b831b9c3c07eeacd8ce0dff"
        yarahub_uuid = "dd11687f-5692-4b4b-800a-704e63cf52c6"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.redline_stealer"
        version = "1"
    strings:
        $string_0 = "UNKNOWN" wide
        $string_1 = "*wallet*" wide
        $string_2 = "https://api.ip.sb/ip" wide
        $string_3 = "windows-1251" wide
        $string_4 = "{0}{1}{2}" wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}rule win32_safengine {
    meta:
        author = "Reedus0"
        description = "Rule for detecting safengine packer"
        date = "2025-02-12"
        yarahub_reference_md5 = "0c93cdb7a0be26411401c05267f51d8b"
        yarahub_uuid = "e5d75527-948f-4e4b-9a46-181fa2e2a8ed"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:
        $string_0 = "Safengine Shielden v2.4.0.0"
        $string_1 = ".sedata"
    condition:
        uint16(0) == 0x5A4D and $string_0 and #string_1 >= 2
}    import "pe"

rule win32_smoke_loader {
    meta:
        author = "Reedus0"
        description = "Rule for detecting SmokeLoader malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "3863A31031F20C75A411FC8893B36177"
        yarahub_uuid = "9591d18a-1eae-4cfd-bac8-77c2269b420a"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.smokeloader"
        version = "1"
    strings:
        $string_0 = { E8 00 00 00 00 75 ?? 74 ?? }
    condition:
        uint16(0) == 0x5A4D and #string_0 >= 2 and pe.image_base == 0x400000
}rule win32_ux_cryptor{
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
}    import "pe"

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
}rule win32_xworm {
    meta:
        author = "Reedus0"
        description = "Rule for detecting XWorm malware"
        date = "2024-01-29"
        yarahub_reference_md5 = "C0D9BE7234912E8A19D5BA31A4AAA324"
        yarahub_uuid = "407232ed-d7fb-4440-a061-25572f9a9b29"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        malpedia_family = "win.xworm"
        version = "1"
    strings:
        $string_0 = { 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 08
        72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 }
        $string_1 = "@echo off" wide
        $string_2 = "timeout 3 > NUL" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}rule win32_younglotus {
    meta:
        author = "Reedus0"
        description = "Rule for detecting YoungLotus malware"
        date = "2024-07-08"
        yarahub_reference_link = "https://habr.com/ru/articles/827184/"
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
        yarahub_reference_md5 = "74D876023652002FC403052229ADC44E"
        yarahub_uuid = "6754bc2a-adc1-4970-a04d-561098812946"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.younglotus"
        version = "2"
    strings:
        $string_0 = "%s:%d:%s"
        $string_1 = "SYSTEM\\CurrentControlSet\\Services\\"
        $string_2 = "WinSta0\\Default"
        $string_3 = "%4d-%.2d-%.2d %.2d:%.2d"
        $string_4 = "%d*%sMHz"
        $string_5 = "Win7"
        $string_6 = "Shellex"
        $string_7 = "%s%s%s%s%s%s"
        $string_8 = "AVtype_info"
    condition:
        uint16(0) == 0x5A4D and 4 of them and filesize < 300KB
}