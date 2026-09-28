rule HEALTHBANE_Email_Headers
{
	meta:
		author = "Tristeceratops"
		description = "Detects HEALTHBANE-style phishing email headers and lure indicators."
		date = "2026-09-28"
		reference = "HC3-2026-HEALTHBANE-001"
		expected_true_positives = "healthbane_email_01.eml, healthbane_email_02.eml, healthbane_email_03.eml"
		expected_true_negatives = "benign_newsletter.eml"
		confidence = "high when all three evidence families match"

	strings:
		// Header/tooling family. The custom-build token covers minor X-Mailer variation.
		$mailer_version = /PHPMailer[ -]?6\.6\.0/i
		$mailer_custom = /X-Mailer:\s*PHPMailer[^\r\n]*/i

		// Urgency/high-priority family.
		$priority_header = /X-Priority:\s*[12]/i
		$urgent_subject = /Subject:\s*[^\r\n]*(urgent|final notice|action required)/i

		// Healthcare lure family.
		$healthcare_keyword = /\b(staff portal|staff account|benefits|invoice|medical supplies|healthcare|enrollment)\b/i

		// Lookalike healthcare sender family. This is intentionally domain-focused,
		// not a broad match on every external sender.
		$lookalike_sender = /(?:Return-Path|From):[^\r\n]*@(meddefense|medequip-supplies|meddefense-benefits|outlook-protection)\.(?:com|net|org)/i
		$phishing_url = /https?:\/\/(?:meddefense-portal|medequip-supplies|meddefense-benefits|outlook-protection)\.(?:com|net|org)\//i

	condition:
		// Require an EML-like header context and three independent evidence families.
		1 of ($mailer_version, $mailer_custom)
		and 1 of ($priority_header, $urgent_subject)
		and 1 of ($lookalike_sender, $phishing_url)
		and $healthcare_keyword
}


rule HEALTHBANE_Document_Metadata
{
	meta:
		author = "Tristeceratops"
		description = "Detects HEALTHBANE-style PDF or document lure metadata and credential-harvesting content."
		date = "2026-09-28"
		reference = "HC3-2026-HEALTHBANE-001"
		expected_true_positives = "phishing_sample.pdf, healthbane_lure_02.pdf"
		expected_true_negatives = "clean_invoice.pdf, benign_invoice.pdf"
		confidence = "medium"

	strings:
		// PDF and document/tooling indicators.
		$pdf_magic = { 25 50 44 46 }
		$wkhtmltopdf = "wkhtmltopdf" nocase

		// Credential-harvesting paths and campaign parameters.
		$path_verify = "/verify" nocase
		$path_login = "/login" nocase
		$path_portal = "/portal" nocase
		$path_enroll = "/enroll" nocase
		$param_token = "token=" nocase
		$param_id = "id=" nocase

		// Healthcare lure text from the supplied parsed samples.
		$lure_staff = /staff\s+portal|staff\s+access|account\s+verification/i
		$lure_invoice = /invoice|payment\s+overdue|insurance\s+claim/i
		$lure_benefits = /benefits|enrollment|medical\s+suppl(?:y|ies)/i

	condition:
		// The PDF signature is required for the supplied PDF corpus. Documents
		// without a PDF header can still be handled by the composite rule.
		$pdf_magic at 0
		and $wkhtmltopdf
		and 2 of ($path_verify, $path_login, $path_portal, $path_enroll, $param_token, $param_id)
		and 1 of ($lure_staff, $lure_invoice, $lure_benefits)
}


rule HEALTHBANE_Campaign_Composite
{
	meta:
		author = "Tristeceratops"
		description = "Detects stronger HEALTHBANE campaign evidence by combining independent behavior families."
		date = "2026-09-28"
		reference = "HC3-2026-HEALTHBANE-001"
		expected_true_positives = "HEALTHBANE email samples and lure documents containing multiple campaign families"
		expected_true_negatives = "benign newsletter and unrelated clean invoices"
		confidence = "high when two or more families are present"

	strings:
		// Email header family, including the custom X-Mailer variation.
		$email_mailer = /(?:X-Mailer:\s*)?PHPMailer(?:[ -]?6\.6\.0|[^\r\n]*custom build)/i
		$email_priority = /X-Priority:\s*[12]/i
		$email_sender = /@(meddefense-portal|medequip-supplies|meddefense-benefits|outlook-protection)\.(?:com|net|org)/i
		$email_lure = /https?:\/\/[^\r\n]*(?:\/verify|\/login|\/portal|\/enroll)[^\r\n]*/i

		// Document metadata and lure family.
		$doc_tool = "wkhtmltopdf" nocase
		$doc_path = /\/(?:verify|login|portal|enroll)\b/i
		$doc_parameter = /(?:token|id)=/i
		$doc_healthcare = /(?:staff\s+portal|benefits|invoice|healthcare|medical\s+supplies|enrollment)/i

	condition:
		// Strong email evidence: tooling/header plus priority and a lure/sender.
		(
			1 of ($email_mailer)
			and 1 of ($email_priority)
			and 1 of ($email_sender, $email_lure)
			and $doc_healthcare
		)
		or
		// Strong document evidence: tooling plus a credential path/parameter
		// and healthcare lure language.
		(
			$doc_tool
			and 1 of ($doc_path, $doc_parameter)
			and $doc_healthcare
		)
}
