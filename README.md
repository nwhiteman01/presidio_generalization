# Presidio Generalization
A program that sanitizes text using Presidio and custom rules

# Use
- Run using python ./assign4.py
- Insert text you want sanitized and press enter
- Type 'exit' to escape

# What it can do
- Sanitizes default Presidio entities (ie. LOCATION, DATE, etc...)
- Sanitizes custom entites (ie. ORG, USERNAME, and GEN_AMOUNT)
    - ORG is a custom built list, to add more orgs update the deny_list on line 71
    - USERNAME is based around the pattern of [ALPHANUM]_[ALPHANUM] other usernames styles would need to be hardcoded
- Uses generalization for dollar amounts, built around ranges from milions to single digits

# To add custom rules
- Put them in the sanitize_text_with_generalization() function and add the rule to the registry, this allows Presidio to utilize it when analyzing it.

# Sources
- https://microsoft.github.io/presidio/
