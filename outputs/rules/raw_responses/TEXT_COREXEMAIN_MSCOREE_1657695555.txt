rule TEXT_COREXEMAIN_MSCOREE_1657695555
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log traces of a corexemain + mscoree.dll cluster with TimeDateStamp 1657695555 and matching PE header fingerprints (tuned to exclude provided benign neighbors)."
        reference_sha256 = "0ae5656c6ad16162d08b5d3ffb245cf52cacb6b4197d548553611ad2267216ee"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* runtime / loader markers (required) */
        $s_corexemain   = "corexemain" ascii nocase
        $s_mscoree      = "mscoree.dll" ascii nocase

        /* strong timestamp discriminator observed in this malicious cluster */
        $h_tstamp       = "TimeDateStamp is 1657695555" ascii

        /* high-fidelity PE header / section fingerprints (text-log form) */
        $h_sections3    = "NumberOfSections is 3" ascii
        $h_sizecode     = "SizeOfCode is 739328" ascii
        $h_sizeimage    = "SizeOfImage is 770048" ascii
        $h_text_raw     = "text_SizeOfRawData is 739328" ascii
        $h_aep          = "AddressOfEntryPoint is 735126" ascii
        $h_lfanew128    = "e_lfanew is 128" ascii

    condition:
        /*
         * Conservative detection logic:
         *  - Must contain both loader markers (corexemain + mscoree.dll)
         *  - Must contain the exact TimeDateStamp observed in malicious positives
         *  - Must show the expected section count (3)
         *  - Must match at least two high-fidelity header/section fingerprints to avoid benign overlaps
         *  - Require e_lfanew 128 as additional corroboration to further reduce false positives
         */
        $s_corexemain and $s_mscoree and $h_tstamp and $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) ) and
        $h_lfanew128
}
