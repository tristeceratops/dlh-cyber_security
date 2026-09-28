rule HEALTHBANE_PDF_Credential_Harvesting
{
    meta:
        author = "Tristeceratops"
        description = "Detects PDFs associated with HEALTHBANE-style credential-harvesting lures using wkhtmltopdf and URL-based login/enrollment paths."
        date = "2026-09-28"
        reference = "HEALTHBANE"
        threat_level = "high"
        confidence = "medium"

    strings:
        // PDF magic bytes.
        $pdf_magic = { 25 50 44 46 }

        // PDF creator/tooling indicator.
        $wkhtmltopdf = "wkhtmltopdf" nocase

        // Credential-harvesting URL paths.
        $path_verify = "/verify" nocase
        $path_login  = "/login" nocase
        $path_portal = "/portal" nocase
        $path_enroll = "/enroll" nocase

        // URL parameters that may carry victim/session identifiers.
        $param_token = "token=" nocase
        $param_id    = "id=" nocase

    condition:
        // Confirm that the file starts with the PDF signature.
        $pdf_magic at 0

        and

        // Require the known creator/tooling string.
        $wkhtmltopdf

        and

        // Require at least two credential-harvesting URL indicators.
        2 of (
            $path_verify,
            $path_login,
            $path_portal,
            $path_enroll,
            $param_token,
            $param_id
        )
}