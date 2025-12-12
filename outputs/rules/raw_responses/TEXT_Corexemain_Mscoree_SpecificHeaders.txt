rule TEXT_Corexemain_Mscoree_SpecificHeaders
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detect corexemain + mscoree.dll entries tied to the specific PE header fingerprint (TimeDateStamp 1621389374 + companion header tokens). Designed to avoid benign neighbors by requiring the exact TimeDateStamp plus another unique header token."
        sha256_target = "ac81425293d072146e810b6b584333f09831ab5c1f3fe20b12f0dbed0913398e"
        created = "2025-11-30"
        tlp = "white"

    strings:
        $corexemain        = "corexemain" ascii nocase
        $mscoree           = "mscoree.dll" ascii nocase

        /* Strongly distinguishing header tokens (text-log form) */
        $t_timestamp       = "TimeDateStamp is 1621389374" ascii
        $s_sizeofcode      = "SizeOfCode is 480768" ascii
        $s_aep             = "AddressOfEntryPoint is 488758" ascii
        $s_text_raw        = "text_SizeOfRawData is 480768" ascii
        $s_sizeofimage     = "SizeOfImage is 507904" ascii
        $s_rsrc_raw        = "rsrc_SizeOfRawData is 7680" ascii

    condition:
        /*
         * Require runtime loader tokens AND the exact TimeDateStamp found in the malicious sample,
         * plus at least one additional specific PE header token to reduce false positives against benign .NET artifacts.
         */
        $corexemain and $mscoree and $t_timestamp and
        ( $s_sizeofcode or $s_aep or $s_text_raw or $s_sizeofimage or $s_rsrc_raw )
}
