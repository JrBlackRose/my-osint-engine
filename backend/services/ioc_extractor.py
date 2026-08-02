import re

def normalize_malay_spoken_numbers(text: str) -> str:
    """Converts common Malay spoken number words into digits so regex can catch them from Whisper output."""
    replacements = {
        "kosong": "0", "satu": "1", "dua": "2", "tiga": "3", "empat": "4",
        "lima": "5", "enam": "6", "tujuh": "7", "lapan": "8", "sembilan": "9",
        "satu-satunya": "1"
    }
    
    # Simple word substitution for numbers
    words = text.split()
    normalized_words = [replacements.get(w.lower(), w) for w in words]
    return " ".join(normalized_words)

def extract_iocs(text: str) -> dict:
    # First normalize any spoken numbers from audio transcriptions
    processed_text = normalize_malay_spoken_numbers(text)

    phone_pattern = r"(?:\+?60|0060|0)[1]\d{1}(?:[- \s]?)\d{3,4}(?:[- \s]?)\d{4}\b"
    bank_pattern = r"\b(?:\d[- \s]*){10,14}\b"

    raw_phones = re.findall(phone_pattern, processed_text)
    raw_banks = re.findall(bank_pattern, processed_text)

    cleaned_phones = []
    phone_filter_set = set()

    for p in raw_phones:
        clean_p = re.sub(r"[- \s]", "", p)
        if clean_p.startswith("+60"):
            local_format = "0" + clean_p[3:]
            int_format = clean_p[1:]
        elif clean_p.startswith("60"):
            local_format = "0" + clean_p[2:]
            int_format = clean_p
        else:
            local_format = clean_p
            int_format = "60" + clean_p[1:] if clean_p.startswith("0") else clean_p
            
        cleaned_phones.append(local_format)
        phone_filter_set.update([local_format, int_format, clean_p])

    cleaned_phones = list(set(cleaned_phones))

    cleaned_banks = []
    for b in raw_banks:
        clean_b = re.sub(r"[- \s]", "", b)
        if clean_b not in phone_filter_set:
            cleaned_banks.append(clean_b)

    cleaned_banks = list(set(cleaned_banks))

    return {
        "phone_numbers": cleaned_phones,
        "bank_accounts": cleaned_banks
    }
