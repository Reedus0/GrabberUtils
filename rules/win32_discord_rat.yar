rule win32_discord_rat{
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
}    