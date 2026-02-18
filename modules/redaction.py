import re
import io
import fitz # PyMuPDF

class RedactionEngine:
    """
    Handles automatic redaction of sensitive PII (NRIC, Phone, Salary) 
    and sanitization of hyperlinks.
    """

    # --- PII Patterns ---
    # NRIC: Start with S/T/F/G, 7 digits, End with letter. (Simple Regex)
    REGEX_NRIC = r'(?i)\b([STFG])\d{7}[A-Z]\b'
    
    # Phone: Singapore 8-digit numbers starting with 6, 8, 9. 
    REGEX_PHONE = r'(?<!\d)(6|8|9)\d{3}[\s-]?\d{4}(?!\d)'
    
    # Salary: $1,234.56 or $5000 or 5000 SGD.
    REGEX_SALARY = r'\$\s?[\d,]+(\.\d{2})?|[\d,]+\s?SGD'

    def __init__(self):
        pass

    def redact_nric(self, text):
        """Masks NRICs to SXXXX123A format."""
        def mask(match):
            original = match.group(0)
            if len(original) >= 9:
                return original[0] + 'XXXX' + original[-4:]
            return '********'
        return re.sub(self.REGEX_NRIC, mask, text)

    def redact_phone(self, text):
        """Masks phone numbers to 9xxx 4567."""
        def mask(match):
            s = match.group(0)
            # Remove spaces/dashes for processing
            clean = re.sub(r'[\s-]', '', s)
            return clean[0] + 'xxx ' + clean[-4:]
        return re.sub(self.REGEX_PHONE, mask, text)

    def redact_financials(self, text):
        """Redacts salary figures."""
        return re.sub(self.REGEX_SALARY, '[REDACTED_FINANCIAL]', text)

    def sanitize_links(self, text):
        """Removes dangerous schemes and tracking params."""
        def clean_url(match):
            return '[REDACTED_LINK]'
        
        # Simple URL pattern
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return re.sub(url_pattern, clean_url, text)

    def process(self, content: str, mime_type: str = 'text/plain') -> str:
        """
        Main entry point for TEXT string redaction.
        """
        if 'image' in mime_type:
             return content 
        
        redacted = content
        redacted = self.redact_nric(redacted)
        redacted = self.redact_phone(redacted)
        redacted = self.redact_financials(redacted)
        redacted = self.sanitize_links(redacted)
        
        return redacted

    def process_pdf(self, file_bytes: bytes) -> bytes:
        """
        Redacts PII from PDF files using PyMuPDF.
        Returns redacted PDF bytes.
        """
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            
            # Patterns to search for
            patterns = [
                self.REGEX_NRIC,
                self.REGEX_PHONE,
                self.REGEX_SALARY
            ]
            
            for page in doc:
                # 1. Extract text to find matches
                page_text = page.get_text()
                
                for pattern in patterns:
                    # 2. Find all regex matches in the text
                    # We iterate over matches and search for the specific matched string
                    for match in re.finditer(pattern, page_text):
                        highlight_text = match.group(0)
                        
                        # 3. Search for the literal string on the page to get coordinates
                        # quad=True generally gives better bounding boxes for redaction
                        hits = page.search_for(highlight_text)
                        
                        for rect in hits:
                            # Add a redaction annotation (black box)
                            page.add_redact_annot(rect, fill=(0, 0, 0))
                
                # Apply the redactions to the page content
                page.apply_redactions()
                
            # Save to a new bytes buffer
            output_buffer = io.BytesIO()
            doc.save(output_buffer)
            return output_buffer.getvalue()
            
        except Exception as e:
            print(f"PDF Redaction Error: {e}")
            # If redaction fails, return original (or raise error based on policy)
            return file_bytes

    def process_file_stream(self, file_stream, mime_type='text/plain'):
        """
        Reads stream, redacts, returns new bytes.
        """
        # 1. Handle PDF
        if mime_type == 'application/pdf':
            file_bytes = file_stream.read()
            return self.process_pdf(file_bytes)
            
        # 2. Handle Text
        elif mime_type.startswith('text/'):
            text = file_stream.read().decode('utf-8', errors='ignore')
            redacted_text = self.process(text, mime_type)
            return redacted_text.encode('utf-8')
            
        # 3. Handle Binary/Unknown - Pass through
        else:
            return file_stream.read()
