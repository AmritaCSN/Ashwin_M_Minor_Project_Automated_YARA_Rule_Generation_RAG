rule TEXT_COREXEMAIN_MSCOREE_1651459917
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a .NET/native loader cluster: requires corexemain + mscoree.dll plus the unique TimeDateStamp 1651459917 and large PE header fingerprints observed in malicious neighbors. Tuned to avoid the supplied benign neighbors."
        tlp = "white"
        created = "2025-11-30"

    strings:
        /* Required runtime markers (common to this family but also present in benigns — used only in combination) */
        $s_corexemain     = "corexemain" ascii nocase
        $s_mscoree        = "mscoree.dll" ascii nocase

        /* Strong unique header / fingerprint tokens (text-log form) observed across malware neighbors */
        $h_timestamp      = "TimeDateStamp is 1651459917" ascii
        $h_sizecode       = "SizeOfCode is 976384" ascii
        $h_sizeimage      = "SizeOfImage is 1007616" ascii
        $h_text_raw       = "text_SizeOfRawData is 976384" ascii
        $h_rsrc_vsize     = "rsrc_Misc_VirtualSize is 1444" ascii
        $h_rsrc_raw       = "rsrc_SizeOfRawData is 1536" ascii
        $h_sections3      = "NumberOfSections is 3" ascii

    condition:
        /*
         * Conservative, high-confidence logic:
         *  - Require both family markers to narrow to .NET/native loader traces.
         *  - Require the exact TimeDateStamp for this malicious cluster (strong discriminator).
         *  - Require at least two high-fidelity header fingerprints (large code/image/text sizes or resource sizes).
         *
         * This avoids matching benign samples that may contain corexemain/mscoree.dll but do NOT share the precise
         * combination of timestamp and large header values present in the malicious neighbors.
         */
        $s_corexemain and $s_mscoree and $h_timestamp and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_rsrc_vsize, $h_rsrc_raw, $h_sections3 ) )
}
