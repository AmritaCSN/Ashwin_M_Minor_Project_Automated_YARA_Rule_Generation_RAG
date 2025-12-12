rule VB6_GDIPlus_Image_Worker_a3f0b147
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log indicators of a VB6 + GDI+ image/graphics worker (gdiplus.dll + msvbvm60.dll + VB runtime symbols). Tuned to avoid matching common C/C++ or POSIX binaries in negatives."
        sha256 = "a3f0b147f9803f7461689734db17334d4237ea309737e340b167aee5209591b3"
        tlp = "WHITE"
        created = "2025-11-30"

    strings:
        /* runtime / DLL markers (very specific to this sample) */
        $dll_gdiplus            = "gdiplus.dll" nocase
        $dll_msvb               = "msvbvm60.dll" nocase

        /* GDI+ / graphics APIs (uncommon in benign neighbors) */
        $g_gdiplus_startup      = "gdiplusstartup" nocase
        $g_gdiplus_shutdown     = "gdiplusshutdown" nocase
        $g_create_from_hdc      = "gdipcreatefromhdc" nocase
        $g_dispose_image        = "gdipdisposeimage" nocase
        $g_delete_graphics      = "gdipdeletegraphics" nocase
        $g_create_pen1          = "gdipcreatepen1" nocase
        $g_create_brush         = "gdipcreatesolidfill" nocase
        $g_draw_image_rect      = "gdipdrawimagerect" nocase
        $g_fill_rectangle       = "gdipfillrectangle" nocase
        $g_measure_string       = "gdipmeasurestring" nocase
        $g_create_bitmap_hbitmap= "gdipcreatebitmapfromhbitmap" nocase
        $g_create_hatchbrush    = "gdipcreatehatchbrush" nocase
        $g_set_smoothing        = "gdipsetsmoothingmode" nocase

        /* VB6/COM runtime symbols and helpers (very specific; reduces false positives) */
        $v_vbafreevar           = "vbafreevar" nocase
        $v_vbafreeobj           = "vbafreeobj" nocase
        $v_vbafileopen          = "vbafileopen" nocase
        $v_vbafileclose         = "vbafileclose" nocase
        $v_vbaexitproc          = "vbastexe" nocase  /* seen as vbastopexe in sample */
        $v_vbastrcopy           = "vbastrcopy" nocase
        $v_vbar8str             = "vbar8str" nocase
        $v_vbavarsetobj         = "vbavarsetobj" nocase
        $v_eventsink_invoke     = "eventsinkinvoke" nocase
        $v_zombie_get_typeinfo  = "zombiegettypeinfo" nocase

    condition:
        // Target is a text log. Require both the GDI+ runtime AND the VB6 runtime DLL names
        // plus at least four distinct GDI+/VB symbols to minimize false positives against benign neighbors.
        $dll_gdiplus and $dll_msvb and 4 of (
            $g_gdiplus_startup, $g_gdiplus_shutdown, $g_create_from_hdc, $g_dispose_image,
            $g_delete_graphics, $g_create_pen1, $g_create_brush, $g_draw_image_rect,
            $g_fill_rectangle, $g_measure_string, $g_create_bitmap_hbitmap, $g_create_hatchbrush,
            $g_set_smoothing,
            $v_vbafreevar, $v_vbafreeobj, $v_vbafileopen, $v_vbafileclose,
            $v_vbaexitproc, $v_vbastrcopy, $v_vbar8str, $v_vbavarsetobj,
            $v_eventsink_invoke, $v_zombie_get_typeinfo
        )
}
