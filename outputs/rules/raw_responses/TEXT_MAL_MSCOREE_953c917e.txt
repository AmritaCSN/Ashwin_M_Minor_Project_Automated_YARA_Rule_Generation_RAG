rule TEXT_MAL_MSCOREE_953c917e
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a mscoree/.NET loader cluster: combines corexemain + mscoree.dll with a strict header fingerprint (timestamp + section/raw-size) to avoid benign neighbors."
        sha256_target = "953c917ea98a8b9eff67f260709fb55980c614c2d87dbb399c77a3ec682fe00e"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavioral tokens (must appear together in text logs) */
        $a_corexemain    = "corexemain" ascii nocase
        $a_mscoree       = "mscoree.dll" ascii nocase

        /* precise header / fingerprint tokens (text-log form) */
        $h_timestmp      = "TimeDateStamp is 4239979505" ascii
        $h_text_raw      = "text_SizeOfRawData is 322048" ascii
        $h_sections3     = "NumberOfSections is 3" ascii
        $h_lfanew128     = "e_lfanew is 128" ascii

        /* resource-area exact sizes/offsets (helps separate similar benigns) */
        $h_rsrc_raw1024  = "rsrc_SizeOfRawData is 1024" ascii
        $h_rsrc_ptr322560= "rsrc_PointerToRawData is 322560" ascii

    condition:
        /*
         * Require:
         *  - both cluster-identifying tokens (corexemain + mscoree.dll), AND
         *  - the unique timestamp AND the exact text raw-size, AND
         *  - at least one additional header/resource token to avoid matching benigns that share basic fields.
         */
        $a_corexemain and
        $a_mscoree and
        $h_timestmp and
        $h_text_raw and
        ( any of ( $h_sections3, $h_lfanew128, $h_rsrc_raw1024, $h_rsrc_ptr322560 ) )
}
