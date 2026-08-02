import re

def normalize_malay_spoken_numbers(text: str) -> str:
    """Converts common Malay spoken number words into digits for Whisper transcriptions."""
    replacements = {
        "kosong": "0", "satu": "1", "dua": "2", "tiga": "3", "empat": "4",
        "lima": "5", "enam": "6", "tujuh": "7", "lapan": "8", "sembilan": "9"
    }

    words = text.split()
    normalized_words = [replacements.get(w.lower(), w) for w in words]
    return " ".join(normalized_words)

def extract_iocs(text: str) -> dict:
    processed_text = normalize_malay_spoken_numbers(text)

    # 1. URL Pattern (Matches http/https and bare domains like shopee-vip-task88.com/register)
    url_pattern = r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?\b'
    
    # 2. Phone Patterns: Malaysian (01X, +601X, 03) AND US / Toll-Free (1-800-555-0199, +1-800)
    my_phone_pattern = r"(?:\+?60|0060|0)[1-9]\d{1}(?:[- \s]?)\d{3,4}(?:[- \s]?)\d{4}\b"
    toll_free_pattern = r"\b(?:\+?1[- \s]?)?1?[- \s]?8[0-9]{2}[- \s]?[0-9]{3}[- \s]?[0-9]{4}\b"

    # 3. Bank Account Pattern (10 to 14 digits)
    bank_pattern = r"\b\d{10,14}\b"

    # 4. IP Address Pattern (IPv4)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    # Extract URLs first
    raw_urls = re.findall(url_pattern, processed_text)
    cleaned_urls = [u for u in set(raw_urls) if not u.endswith(('.png', '.jpg', '.jpeg'))]

    # Extract Phones
    my_phones = re.findall(my_phone_pattern, processed_text)
    toll_free_phones = re.findall(toll_free_pattern, processed_text)
    
    all_raw_phones = my_phones + toll_free_phones
    cleaned_phones = []
    phone_digits_set = set()

    for p in all_raw_phones:
        clean_digits = re.sub(r"[^\d]", "", p)
        phone_digits_set.add(clean_digits)
        
        # Standardize formatting
        if clean_digits.startswith("60"):
            cleaned_phones.append("0" + clean_digits[2:])
        else:
            cleaned_phones.append(p.strip())

    cleaned_phones = list(set(cleaned_phones))

    # Extract IP Addresses
    raw_ips = re.findall(ip_pattern, processed_text)
    cleaned_ips = []
    for ip in raw_ips:
        # Ensure valid octets (0-255)
        if all(0 <= int(octet) <= 255 for octet in ip.split('.')):
            cleaned_ips.append(ip)
    cleaned_ips = list(set(cleaned_ips))

    # Extract Bank Accounts (excluding matched phone digit strings)
    raw_banks = re.findall(bank_pattern, processed_text)
    cleaned_banks = []

    for b in raw_banks:
        clean_b = re.sub(r"[^\d]", "", b)
        # Avoid tagging phone numbers as bank accounts
        if clean_b not in phone_digits_set:
            cleaned_banks.append(clean_b)

    cleaned_banks = list(set(cleaned_banks))

    return {
        "phone_numbers": cleaned_phones,
        "bank_accounts": cleaned_banks,
        "urls": cleaned_urls,
        "ip_addresses": cleaned_ips
    }
