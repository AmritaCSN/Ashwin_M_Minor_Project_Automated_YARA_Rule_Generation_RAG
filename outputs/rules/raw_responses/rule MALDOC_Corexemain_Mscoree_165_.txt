rule MALDOC_Corexemain_Mscoree_165_FileAlign1024
{
    meta:
        author = "assistant"
        description = "Text-log rule: detects records referencing 'corexemain' + 'mscoree.dll' together with MajorLinkerVersion 48 and 165xxxxxxx TimeDateStamp and 1024 FileAlignment/SizeOfHeaders — chosen to separate malicious neighbors from benign examples."
        reference_sha256 = "11a5857ee8a80ec2f7e9ce6dcf16af5495bf680f37d6750fc64d699a8ac904d5"
        date = "2025-12-01"
        confidence = 90

    strings:
        $s_corexemain        = "corexemain"
        $s_mscoree           = "mscoree.dll"
        $s_linker48          = "MajorLinkerVersion is 48"
        $s_filealign_1024    = "FileAlignment is 1024"
        $s_sizeofhdr_1024    = "SizeOfHeaders is 1024"
        /* TimeDateStamp values observed in malicious neighbors (e.g. 1650847165). Match 10-digit values starting with 165 */
        $re_tds_165          = /TimeDateStamp is 165[0-9]{7}/

    condition:
        /* require the characteristic import/API text plus the linker anomaly and the malicious timestamp family,
           and require evidence of 1024 alignment/headers to avoid benigns (which use 4096 in negatives) */
        all of ($s_corexemain, $s_mscoree) and $s_linker48 and $re_tds_165 and ( $s_filealign_1024 or $s_sizeofhdr_1024 )
}
