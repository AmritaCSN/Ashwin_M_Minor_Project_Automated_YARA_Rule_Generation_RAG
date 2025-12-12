rule TEXT_COREXEMAIN_MSOCOHORT_25f1faa2
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detect corexemain + mscoree.dll samples from the specific .NET/native loader cluster (precision tuned to avoid provided benign neighbors)."
        reference_sha256 = "25f1faa21822093733dca0e351a69073d713e3c698ce130b02bf9ec93576bf21"
        created = "2025-12-01"
        tlp = "white"

    strings:
        /* High-signal markers (present in positives) */
        $s_corexemain       = "corexemain" ascii nocase
        $s_mscoree          = "mscoree.dll" ascii nocase

        /* Unique header fingerprint for this malicious cluster (text-log form) */
        $t_timestamp        = "TimeDateStamp is 1647246671" ascii

        /* Structural tokens shared by the cluster (avoid matching benigns by requiring multiple together) */
        $h_lfanew128        = "e_lfanew is 128" ascii
        $h_sections_3       = "NumberOfSections is 3" ascii
        $h_filealign_512    = "FileAlignment is 512" ascii

        /* Large/precise size tokens that differentiate this cluster from benign neighbors */
        $h_sizecode_980992  = "SizeOfCode is 980992" ascii
        $h_text_raw_980992  = "text_SizeOfRawData is 980992" ascii
        $h_rsrc_ptr_981504  = "rsrc_PointerToRawData is 981504" ascii

    condition:
        /*
         * Matching logic:
         *  - require both high-signal tokens (corexemain + mscoree.dll)
         *  - require the exact TimeDateStamp seen in this sample
         *  - require core structural layout (e_lfanew + NumberOfSections + FileAlignment)
         *  - plus at least one of the large/precise size tokens to avoid benign overlaps
         */
        $s_corexemain and $s_mscoree and
        $t_timestamp and
        $h_lfanew128 and $h_sections_3 and $h_filealign_512 and
        (1 of ($h_sizecode_980992, $h_text_raw_980992, $h_rsrc_ptr_981504))
}
