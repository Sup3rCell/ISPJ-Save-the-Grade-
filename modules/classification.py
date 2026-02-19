import re

class DocumentClassifier:
    """
    Analyzes document content to determine appropriate security classification.
    """
    
    # Classification Levels
    PUBLIC = 'public'
    INTERNAL = 'internal'
    CONFIDENTIAL = 'confidential'
    RESTRICTED = 'restricted'
    
    # Priority (Higher index = Higher sensitivity)
    LEVELS = [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED]

    def __init__(self):
        self.keywords = {
            self.RESTRICTED: [
                r'strictly private', 
                r'do not distribute', 
                r'password', 
                r'secret',
                r'salary',
                r'bank account'
            ],
            self.CONFIDENTIAL: [
                r'confidential', 
                r'internal use only', 
                r'proprietary',
                r'private'
            ]
        }
        
        # Regex patterns for sensitive data detection
        self.regex_patterns = {
            self.RESTRICTED: [
                r'(?i)([STFG])\d{7}[A-Z]',  # NRIC
                r'\b\d{16}\b',              # Credit Card (Simple)
            ],
            self.CONFIDENTIAL: [
                r'(?<!\d)(6|8|9)\d{3}\s?\d{4}(?!\d)', # Phone
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' # Email
            ]
        }

    def classify(self, content: str, manual_selection: str = 'internal') -> dict:
        """
        Determines the classification level based on content analysis.
        Returns a dict with 'level' and 'reasons'.
        """
        content_lower = content.lower()
        detected_level = self.INTERNAL # Default baseline
        reasons = []

        # 1. Check Restricted Keywords/Patterns (Zero Tolerance)
        # Any single match triggers Restricted
        r_keywords, r_patterns, r_details = self._count_matches(content, content_lower, self.RESTRICTED)
        if r_keywords + r_patterns > 0:
            detected_level = self.RESTRICTED
            reasons.append(f"Detected Restricted content: {', '.join(r_details)}")
        
        # 2. Check Confidential (Frequency Based)
        # Keywords are strong indicators (Threshold 1)
        # PII Patterns (Emails, Phone) need frequency (Threshold 3)
        else:
            c_keywords, c_patterns, c_details = self._count_matches(content, content_lower, self.CONFIDENTIAL)
            
            if c_keywords >= 1:
                detected_level = self.CONFIDENTIAL
                reasons.append(f"Detected Confidential keywords: {', '.join(c_details)}")
            elif c_patterns >= 3:
                detected_level = self.CONFIDENTIAL
                reasons.append(f"Detected high frequency of PII ({c_patterns} matches): {', '.join(c_details)}")

        # 3. Compare with Manual Selection
        final_level = self._resolve_level(manual_selection, detected_level)
        
        if final_level != manual_selection:
            reasons.append(f"System upgraded classification from {manual_selection} to {final_level}")

        return {
            'level': final_level,
            'system_level': detected_level,
            'reasons': reasons
        }

    def _count_matches(self, content, content_lower, level):
        """
        Counts occurrences of keywords and regex patterns for a given level.
        Returns (keyword_count, pattern_count, details_list)
        """
        keyword_count = 0
        pattern_count = 0
        details = []
        
        # Check Keywords
        for kw in self.keywords.get(level, []):
            count = content_lower.count(kw)
            if count > 0:
                keyword_count += count
                details.append(f"'{kw}' ({count})")
        
        # Check Regex
        for pattern in self.regex_patterns.get(level, []):
            matches = re.findall(pattern, content)
            count = len(matches)
            if count > 0:
                pattern_count += count
                details.append(f"Pattern Matches ({count})")
                
        return keyword_count, pattern_count, details

    def _resolve_level(self, manual, detected):
        """Returns the higher classification level."""
        try:
            manual_idx = self.LEVELS.index(manual.lower())
        except ValueError:
            manual_idx = 0
            
        detected_idx = self.LEVELS.index(detected)
        
        return self.LEVELS[max(manual_idx, detected_idx)]
