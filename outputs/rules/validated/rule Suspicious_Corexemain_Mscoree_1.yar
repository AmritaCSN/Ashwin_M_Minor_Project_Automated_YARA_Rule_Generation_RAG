rule Suspicious_Corexemain_Mscoree_TextLog
{
    meta:
        author = "assistant"
        description = "Detects text/log entries of a malware family that reference 'corexemain' + 'mscoree.dll' combined with an unusually high MajorLinkerVersion (80) and TimeDateStamp values in the 16x... epoch range observed across malicious neighbors. Designed for text logs (no PE imports)."
        reference_sha256 = "706a8a414b5cf5b0af00dc98bc373f48b48e07a7770e2270b5cb6f546f482aba"
        date = "2025-12-01"
        confidence = 90
    strings:
        $s_corexemain      = "corexemain"
        $s_mscoree         = "mscoree.dll"
        $s_linker_80       = "MajorLinkerVersion is 80"
        $s_num_sections_3  = "NumberOfSections is 3"
        /* Match 10-digit TimeDateStamp values beginning with 162.. through 166.. (captures 162xxxxxxx,163...,164...,165...,166...) */
        $re_tds_16x        = /TimeDateStamp is 16[2-6][0-9]{7}/
    condition:
        /* require the specific anomaly (linker 80) AND the runtime stamp pattern plus the known imports/API text */
        all of ($s_corexemain, $s_mscoree) and $s_linker_80 and $re_tds_16x and $s_num_sections_3
}
