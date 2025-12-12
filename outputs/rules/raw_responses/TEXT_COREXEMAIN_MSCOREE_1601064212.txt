rule TEXT_COREXEMAIN_MSCOREE_1601064212
{
    meta:
        author = "malware-analyst"
        description = "High-confidence text-log rule for a .NET/native loader cluster. Requires corexemain + mscoree.dll plus the exact TimeDateStamp (1601064212) and matching PE header size fingerprints observed in the malware neighbors. Tuned to avoid supplied benign neighbors by requiring the precise timestamp + large header combination."
        sha256_target = "8b2c5362887dbc350aae004bee2ea50b83aee63bdb1d88c2559672e9ca5b91d5"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* required family markers (must be present but common in benigns) */
        $s_corexemain    = "corexemain" ascii nocase
        $s_mscoree       = "mscoree.dll" ascii nocase

        /* unique cluster discriminator (strong) */
        $h_timestamp     = "TimeDateStamp is 1601064212" ascii

        /* high-fidelity header fingerprints (text-log form) */
        $h_sizecode      = "SizeOfCode is 35840" ascii
        $h_sizeimage     = "SizeOfImage is 65536" ascii
        $h_text_raw      = "text_SizeOfRawData is 35840" ascii
        $h_rsrc_raw      = "rsrc_SizeOfRawData is 1024" ascii
        $h_sections3     = "NumberOfSections is 3" ascii

    condition:
        /*
         * Detection logic:
         *  - Require both runtime markers to target .NET/native loader traces.
         *  - Require the exact TimeDateStamp seen in the malicious sample (strong discriminator against benigns).
         *  - Require at least two high-fidelity header tokens (sizecode/sizeimage/text_raw/rsrc_raw) to confirm the fingerprint.
         *  - Also require NumberOfSections is 3 (seen across positives) as secondary corroboration.
         */
        $s_corexemain and $s_mscoree and $h_timestamp and
        $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_rsrc_raw ) )
}
