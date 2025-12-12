rule TEXT_WINMM_PECLUSTER_1067389871
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a GUI/audio-capable native cluster (timestamp 1067389871). Requires winmm.dll + the exact TimeDateStamp and multiple high-fidelity PE header tokens seen in the malicious neighbors. Tuned to avoid provided benign neighbors."
        target_sample = "1ebe38986d47f90019956195461098bb545930903e94652efe73b8d4103ca1bb"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* runtime / uncommon DLL (used as a discriminator vs benign set) */
        $dll_winmm        = "winmm.dll" ascii nocase

        /* GUI / audio APIs present in positives but absent from the benign set */
        $api_drawtexta    = "drawtexta" ascii nocase
        $api_playsounda   = "playsounda" ascii nocase

        /* exact strong header discriminator (text-log) */
        $h_timestamp      = "TimeDateStamp is 1067389871" ascii

        /* high-fidelity PE header fingerprints (text-log form) */
        $h_sections3      = "NumberOfSections is 3" ascii
        $h_sizecode       = "SizeOfCode is 258560" ascii
        $h_sizeimage      = "SizeOfImage is 282624" ascii
        $h_text_raw       = "text_SizeOfRawData is 258560" ascii
        $h_aep            = "AddressOfEntryPoint is 237641" ascii

    condition:
        /*
         * Matching logic:
         *  - Require the uncommon DLL (winmm.dll) AND the exact TimeDateStamp (strong discriminator).
         *  - Require the suspicious GUI/audio APIs (at least one) to avoid matching generic runtime-only logs.
         *  - Require NumberOfSections is 3 (seen across positives) to reduce accidental matches.
         *  - Require at least two high-fidelity header fingerprints to confirm the cluster fingerprint.
         */
        $dll_winmm and $h_timestamp and
        ( $api_drawtexta or $api_playsounda ) and
        $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) )
}
