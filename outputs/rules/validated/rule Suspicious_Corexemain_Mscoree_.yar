rule Suspicious_Corexemain_Mscoree_TextLog
{
    meta:
        author = "assistant"
        description = "Detects text-based logs for a malware family that includes 'corexemain' + 'mscoree.dll' and a TimeDateStamp beginning with 165 (matches the provided malicious samples while avoiding listed benign neighbors)."
        reference_sha256 = "7e5d9c7f336e94ee88a9cee55858de158ba66862527ede87e3e7dec7ece79688"
        license = "proprietary"
        date = "2025-12-01"
    strings:
        $s_corexemain      = "corexemain"
        $s_mscoree         = "mscoree.dll"
        $s_tds_165_prefix  = "TimeDateStamp is 165"
        $s_num_sections_3  = "NumberOfSections is 3"
    condition:
        all of ($s_corexemain, $s_mscoree) and $s_tds_165_prefix and $s_num_sections_3
}
