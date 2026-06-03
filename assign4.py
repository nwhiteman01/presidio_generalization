from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

"""
    TECHNIQUE 1: Generalization / k-Anonymization
    generalize dollar amounts:
    e.g., $5       -> Under $10
    e.g., $165,000 -> $150k-$200k
"""
def generalize_amount(text):
    # For the copy and past text stuff
    clean_text = text.replace('$', '').replace(',', '').strip()
    
    try:
        # Handle Millions (e.g., $450M)
        if 'M' in clean_text.upper():
            num = float(clean_text.upper().replace('M', ''))
            lower = int((num // 100) * 100)
            upper = lower + 100
            return f"${lower}M-${upper}M"
        
        num = float(clean_text)
        
        # Six-figure and above (e.g., $165,000) -> Bucket by 50k
        if num >= 100000:
            lower = int((num // 50000) * 50)
            upper = lower + 50
            return f"${lower}k-${upper}k"
            
        # Five-figure salaries/amounts (e.g., $15,000) -> Bucket by 10k
        elif num >= 10000:
            lower = int((num // 10000) * 10)
            upper = lower + 10
            return f"${lower}k-${upper}k"
            
        # Hundreds/Thousands (e.g., $650 or $2,500) -> Bucket by 100s or 1000s
        elif num >= 100:
            step = 1000 if num >= 1000 else 100
            lower = int((num // step) * step)
            upper = lower + step
            return f"${lower}-${upper}"
            
        # Double digits (e.g., $45) -> Bucket by 10s
        elif num >= 10:
            lower = int((num // 10) * 10)
            upper = lower + 10
            return f"${lower}-${upper}"
            
        # Single digits (e.g., $5) -> Generalize as a threshold
        else:
            return "Under $10"
            
    except ValueError:
        return "<GENERALIZED_AMOUNT>"


def sanitize_text_with_generalization(text):
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    text = text.replace("’", "'").replace("‘", "'")

    """
    # TECHNIQUE 2: Guard-rails / Rule-based checking
    # Custom Org Recognizer (Deny List)
    """
    # Check for Orgs
    org_recognizer = PatternRecognizer(
        supported_entity="ORG",
        deny_list=["St. Jude's", "CloudStream Inc.", "Netflix", "Google"]
    )
    analyzer.registry.add_recognizer(org_recognizer)

    # Check for money
    amount_regex = r"\$\d+(?:,\d+)*(?:\.\d+)?(?:[mMkK])?"
    amount_pattern = Pattern(name="amount_pattern", regex=amount_regex, score=0.85)
    
    amount_recognizer = PatternRecognizer(
        supported_entity="GEN_AMOUNT",
        patterns=[amount_pattern]
    )
    analyzer.registry.add_recognizer(amount_recognizer)

    # Check for username
    username_regex = r"\b[a-zA-Z0-9]+_[a-zA-Z0-9]+\b"
    username_pattern = Pattern(name="username_pattern", regex=username_regex, score=0.85)
    
    username_recognizer = PatternRecognizer(
        supported_entity="USERNAME",
        patterns=[username_pattern]
    )
    analyzer.registry.add_recognizer(username_recognizer)

    # Parse text and look for entites
    analyzer_results = analyzer.analyze(
        text=text, 
        entities=["PERSON", "LOCATION", "ORG", "DATE_TIME", "GEN_AMOUNT", "IP_ADDRESS", "USERNAME"], 
        language="en"
    )

    """
    # TECHNIQUE 3: Pseudonymization
    # Replace the real data with redacted or general non-privacy breaking information
    """
    operators = {
        "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
        "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
        "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
        "ORG": OperatorConfig("replace", {"new_value": "<ORGANIZATION>"}),
        "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<SERVER_IP>"}),
        "USERNAME": OperatorConfig("replace", {"new_value": "<USERNAME>"}),
        "GEN_AMOUNT": OperatorConfig(
            "custom", 
            {"lambda": lambda t: generalize_amount(t)}
        )
    }

    # Build the final text
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results,
        operators=operators
    )

    return anonymized_result.text


if __name__ == "__main__":
    print("Type or paste your text below (press Enter to sanitize, or type 'exit' to quit):")
    
    while True:
        user_input = input("\nInput: ")
        
        if user_input.lower() == 'exit':
            print("Exiting sanitizer...")
            break
            
        if not user_input.strip():
            continue
            
        sanitized_text = sanitize_text_with_generalization(user_input)
        
        print("-" * 25)
        print("Sanitized Text:")
        print(sanitized_text)
        print("-" * 25)