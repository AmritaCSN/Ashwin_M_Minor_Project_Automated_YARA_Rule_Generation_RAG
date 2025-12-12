rule VB6_Suspicious_Runtime_Combination
{
    meta:
        author = "expert-malware-analyst"
        description = "Detects VB6/Visual Basic runtime artifacts combined with uncommon VB runtime internals observed across provided malware neighbors. Requires combination of msvbvm60.dll plus multiple VB-internal symbols to reduce false positives."
        sha256_new_sample = "e5e0a549727c9af4b170b6181dd1f69f8f5bfd268ef711c27a1687face31f052"
        date = "2025-12-01"

    strings:
        /* Anchor: VB6 runtime loader */
        $msvb = "msvbvm60.dll" nocase

        /* VB runtime internal symbols (behavioral/implementation-level) —
           these are frequently present in malicious VB6 variants in the positive context
           and are less common in benign apps from the negative context. */
        $vb_varmove                = "vbavarmove" nocase
        $vb_freevarlist            = "vbafreevarlist" nocase
        $vb_freeobjlist            = "vbafreeobjlist" nocase
        $vb_latemem_call_ld        = "vbavarlatememcallld" nocase
        $vb_latemem_st             = "vbavarlatememst" nocase
        $vb_generate_bounds_err    = "vbagenerateboundserror" nocase
        $vb_fp_exception           = "vbafpexception" nocase
        $vb_ary_construct2         = "vbaaryconstruct2" nocase
        $vb_strcat                 = "vbastrcat" nocase
        $vb_instr                  = "vbainstr" nocase

        /* Additional internal helpers seen repeatedly in malware neighbors */
        $cilog                     = "cilog" nocase
        $vba_excep_handler         = "vbaexcepthandler" nocase

    condition:
        /*
         * Detection logic:
         *  - Require the VB6 runtime anchor ($msvb) AND
         *  - At least three distinct VB-internal / implementation symbols from the list.
         *
         * Rationale:
         *  - Many benign apps call common WinAPI names; matching on those alone causes false positives.
         *  - The presence of multiple low-level VB runtime internals together with the VB runtime DLL
         *    is a stronger behavioral indicator of a VB-built sample that contains non-trivial
         *    runtime internals (observed in the malware neighbors) and reduces accidental matches.
         */
        $msvb and 3 of ( $vb_varmove, $vb_freevarlist, $vb_freeobjlist, $vb_latemem_call_ld, $vb_latemem_st, $vb_generate_bounds_err, $vb_fp_exception, $vb_ary_construct2, $vb_strcat, $vb_instr, $cilog, $vba_excep_handler )
}
