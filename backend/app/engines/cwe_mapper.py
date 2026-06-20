"""
CWE Mapper

Maps vulnerability names and descriptions to CWE IDs using:
1. Exact CWE-NNN matches already present on the finding
2. A static keyword -> CWE lookup table for common web vulnerabilities
3. The CweMapping reference table in the database

This enables structured weakness categorisation even when scanners
don't provide CWE information directly.
"""

import re
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.cwe_mapping import CweMapping

# Keyword -> CWE mappings for the most common web vulnerabilities
KEYWORD_CWE_MAP = [
    (r"sql.?inject", "CWE-89"),
    (r"cross.?site.?script|xss", "CWE-79"),
    (r"cross.?site.?request.?forgery|csrf", "CWE-352"),
    (r"path.?traversal|directory.?traversal", "CWE-22"),
    (r"command.?inject|os.?inject|shell.?inject", "CWE-78"),
    (r"xml.?external.?entity|xxe", "CWE-611"),
    (r"insecure.?deseri", "CWE-502"),
    (r"server.?side.?request.?forgery|ssrf", "CWE-918"),
    (r"open.?redirect", "CWE-601"),
    (r"ldap.?inject", "CWE-90"),
    (r"xpath.?inject", "CWE-643"),
    (r"remote.?code.?execut|rce", "CWE-94"),
    (r"file.?upload", "CWE-434"),
    (r"broken.?auth|authentication.?bypass", "CWE-287"),
    (r"missing.?auth|no.?auth", "CWE-306"),
    (r"privilege.?escal|broken.?access", "CWE-269"),
    (r"sensitive.?data|information.?disclos|info.?leak", "CWE-200"),
    (r"clickjack|x.frame", "CWE-1021"),
    (r"security.?misconfigur", "CWE-16"),
    (r"default.?credential|default.?password", "CWE-1392"),
    (r"weak.?password|password.?complexity", "CWE-521"),
    (r"cleartext|plain.?text.?password", "CWE-312"),
    (r"http.?only|cookie", "CWE-1004"),
    (r"hsts|strict.?transport", "CWE-311"),
    (r"cors", "CWE-942"),
    (r"use.?after.?free", "CWE-416"),
    (r"buffer.?overflow", "CWE-120"),
    (r"integer.?overflow", "CWE-190"),
    (r"race.?condition", "CWE-362"),
    (r"null.?pointer|null.?deref", "CWE-476"),
]

# Static CWE descriptions for the reference table seed
CWE_DESCRIPTIONS = {
    "CWE-89": ("SQL Injection", "Web", "A2 Injection"),
    "CWE-79": ("Cross-site Scripting (XSS)", "Web", "A7 XSS"),
    "CWE-352": ("CSRF", "Web", "A1 Broken Access Control"),
    "CWE-22": ("Path Traversal", "Web", "A1 Broken Access Control"),
    "CWE-78": ("OS Command Injection", "Web", "A2 Injection"),
    "CWE-611": ("XML External Entity (XXE)", "Web", "A2 Injection"),
    "CWE-502": ("Insecure Deserialization", "Web", "A8 Software Integrity"),
    "CWE-918": ("SSRF", "Web", "A10 SSRF"),
    "CWE-601": ("Open Redirect", "Web", "A1 Broken Access Control"),
    "CWE-90": ("LDAP Injection", "Web", "A2 Injection"),
    "CWE-94": ("Code Injection / RCE", "Web", "A2 Injection"),
    "CWE-434": ("Unrestricted File Upload", "Web", "A4 Insecure Design"),
    "CWE-287": ("Improper Authentication", "Web", "A7 Auth Failures"),
    "CWE-306": ("Missing Authentication", "Web", "A7 Auth Failures"),
    "CWE-269": ("Improper Privilege Management", "Web", "A1 Broken Access Control"),
    "CWE-200": ("Exposure of Sensitive Information", "Web", "A2 Cryptographic Failures"),
    "CWE-1021": ("Improper Restriction of Rendered UI Layers (Clickjacking)", "Web", "A5 Security Misconfiguration"),
    "CWE-16": ("Configuration", "Web", "A5 Security Misconfiguration"),
    "CWE-521": ("Weak Password Requirements", "Web", "A7 Auth Failures"),
    "CWE-312": ("Cleartext Storage of Sensitive Information", "Web", "A2 Cryptographic Failures"),
    "CWE-1004": ("Sensitive Cookie Without HttpOnly Flag", "Web", "A5 Security Misconfiguration"),
    "CWE-311": ("Missing Encryption of Sensitive Data", "Web", "A2 Cryptographic Failures"),
    "CWE-942": ("Permissive CORS Policy", "Web", "A5 Security Misconfiguration"),
}


class CweMapper:
    def map_finding(self, finding: NormalizedFinding) -> str | None:
        """Return a CWE ID for a finding, updating the finding in place."""
        if finding.cwe_id:
            return finding.cwe_id

        text = " ".join(filter(None, [finding.title, finding.description]))
        cwe_id = self._keyword_match(text)

        if cwe_id:
            finding.cwe_id = cwe_id
            db.session.add(finding)

        return cwe_id

    def map_all_unclassified(self) -> int:
        """Process all findings missing a CWE ID. Returns count updated."""
        findings = NormalizedFinding.query.filter(
            NormalizedFinding.cwe_id.is_(None)
        ).all()
        updated = 0
        for f in findings:
            if self.map_finding(f):
                updated += 1
        db.session.commit()
        return updated

    @staticmethod
    def _keyword_match(text: str) -> str | None:
        text_lower = text.lower()
        for pattern, cwe in KEYWORD_CWE_MAP:
            if re.search(pattern, text_lower):
                return cwe
        return None

    @staticmethod
    def seed_cwe_table() -> int:
        """Populate CweMapping reference table if empty."""
        if CweMapping.query.count() > 0:
            return 0
        added = 0
        for cwe_id, (name, category, owasp) in CWE_DESCRIPTIONS.items():
            mapping = CweMapping(
                cwe_id=cwe_id,
                name=name,
                category=category,
                owasp_category=owasp,
            )
            db.session.add(mapping)
            added += 1
        db.session.commit()
        return added
