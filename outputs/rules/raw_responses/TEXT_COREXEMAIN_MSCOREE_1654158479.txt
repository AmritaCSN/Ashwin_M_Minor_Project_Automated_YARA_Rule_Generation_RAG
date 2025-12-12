rule TEXT_COREXEMAIN_MSCOREE_1654158479
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detects a corexemain + mscoree.dll cluster with TimeDateStamp 1654158479 and matching high-fidelity PE header tokens. Tuned to avoid provided benign neighbors."
        target_sha256 = "31b6be33bdef9d7e8fe37d8725e31a2abe55bbfb962b3c5d0050819624d0cafd"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Required runtime markers (present in positives but common enough to be useful) */
        $s_corexemain   = "corexemain" ascii nocase
        $s_mscoree      = "mscoree.dll" ascii nocase

        /* Strong unique header discriminator for this malicious cluster (text-log form) */
        $h_tstamp       = "TimeDateStamp is 1654158479" ascii

        /* High-fidelity header fingerprints (text-log form) observed across positives */
        $h_sections3    = "NumberOfSections is 3" ascii
        $h_sizecode     = "SizeOfCode is 582144" ascii
        $h_sizeimage    = "SizeOfImage is 614400" ascii
        $h_text_raw     = "text_SizeOfRawData is 582144" ascii
        $h_aep          = "AddressOfEntryPoint is 589914" ascii

    condition:
        /*
         * Detection logic:
         *  - Require both runtime markers (corexemain + mscoree.dll)
         *  - Require the exact TimeDateStamp (strong negative-filter vs benigns)
         *  - Require the common section-count seen in positives (NumberOfSections is 3)
         *  - Require at least two high-fidelity header fingerprints to confirm cluster
         */
        $s_corexemain and $s_mscoree and $h_tstamp and $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) )
}
