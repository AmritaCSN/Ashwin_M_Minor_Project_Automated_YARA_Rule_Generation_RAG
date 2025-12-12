rule TEXT_COREXEMAIN_CLUSTER_2760f661
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detect cluster with corexemain + mscoree.dll and a precise set of PE-header tokens (tuned to avoid provided benign neighbors)."
        reference_sha256 = "2760f66141ee54ef8ac37f1334792b381373e0841bb1a1ae8ab503b353532553"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Required high-signal markers (present in positives and risky if seen together in text logs) */
        $s_corexemain     = "corexemain" ascii nocase
        $s_mscoree        = "mscoree.dll" ascii nocase

        /* Unique/rare header fingerprint for this text-log cluster */
        $t_timestamp      = "TimeDateStamp is 4027361698" ascii

        /* Stable layout tokens shared by cluster but NOT present together in benign neighbors */
        $h_lfanew128      = "e_lfanew is 128" ascii
        $h_sections3      = "NumberOfSections is 3" ascii
        $h_filealign512   = "FileAlignment is 512" ascii
        $h_sizecode95232  = "SizeOfCode is 95232" ascii
        $h_text_raw_95232 = "text_SizeOfRawData is 95232" ascii
        $h_rsrc_ptr_95744 = "rsrc_PointerToRawData is 95744" ascii

    condition:
        /*
         * Decision logic:
         *  - Require the two high-signal tokens (corexemain + mscoree.dll)
         *  - Require the exact TimeDateStamp string observed in this sample
         *  - Require structural confirmation (e_lfanew + NumberOfSections)
         *  - And at least two additional precise header/section tokens to reduce false positives
         */
        $s_corexemain and $s_mscoree and
        $t_timestamp and
        $h_lfanew128 and $h_sections3 and
        (2 of ( $h_filealign512, $h_sizecode95232, $h_text_raw_95232, $h_rsrc_ptr_95744 ))
}
