rule Detect_GDIPlus_Image_Handling_1d14f161
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection: uncommon GDI+ / image-streaming APIs and gdiplus runtime (likely image-processing / loader behavior) — tuned to avoid benign UI/gdi hits."
        sha256 = "1d14f161830af09dbdfca9bbfa554cd9724f8af548495866b29bddf8b4d73a31"
        created = "2025-11-30"
        reference = "Cluster #91 — Target Family Type 2"

    strings:
        $gdiplus_dll                      = "gdiplus.dll" nocase

        /* GDI+ / image-stream APIs (uncommon in benign neighbors) */
        $g1 = "gdiploadimagefromstream" nocase
        $g2 = "gdipcreatebitmapfromstream" nocase
        $g3 = "gdipcreatebitmapfromhicon" nocase
        $g4 = "gdipdrawlinei" nocase
        $g5 = "gdipdrawellipsei" nocase
        $g6 = "gdipsetpencolor" nocase
        $g7 = "gdipemftowmfbits" nocase
        $g8 = "gdipimagegetframedimensionscount" nocase
        $g9 = "gdiprotateworldtransform" nocase
        $g10= "gdipgetpathgradientblend" nocase

        /* additional image / certificate helpers seen in sample */
        $img_cert = "imagegetcertificatedata" nocase
        $write_ole = "writeolestg" nocase
        $stream_write = "writestringstream" nocase

    condition:
        // Target is a text log. To reduce false positives against benign UI/GDI-heavy samples,
        // require the presence of the gdiplus runtime plus at least two distinct uncommon GDI+
        // / image-stream related API names (strong indicator of image-streaming/processing behavior).
        $gdiplus_dll and 2 of ($g*)
        or
        // also match if gdiplus runtime + one GDI+ API plus image certificate/stream helpers appear
        ($gdiplus_dll and 1 of ($g*) and ($img_cert or $write_ole or $stream_write))
}
