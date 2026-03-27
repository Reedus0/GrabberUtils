rule win64_clear_water {
    meta:
        author = "Reedus0"
        description = "Rule for detecting ClearWater ransomware"
        date = "2026-03-26"
        yarahub_reference_md5 = "29145cc1b1400b4b60743a21b075bac7"
        yarahub_uuid = "7c6e1c3a-9c3a-4a2a-91c1-9c4f1e7c52af"
        yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:AMBER"
        yarahub_rule_sharing_tlp = "TLP:AMBER"
        version = "1"
    strings:

        $clearwater = "ClearWater Ransomware Starting" ascii

        $info_txt = "info.txt" ascii
        $clear_ext = ".clear" ascii

        $rsa_log = "[RSA Encrypt]" ascii
        $rsa_blob = "RSAPUBLICBLOB" ascii
        $bcrypt = "BCryptEncrypt" ascii
        $bcrypt_import = "BCryptImportKeyPair" ascii

        $sodium = "sodium_init" ascii
        $chacha = "crypto_stream_chacha20" ascii
        $randombytes = "randombytes_buf" ascii

        $shadow = "vssadmin delete shadows" ascii
        $wmic_shadow = "shadowcopy delete" ascii
        $startup = "CurrentVersion\\Run" ascii
        $wallpaper = "SystemParametersInfo" ascii

        $pubkey = "public_key.pem" ascii
        $magic = { C7 45 10 4D 59 45 4B }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        4 of them
}