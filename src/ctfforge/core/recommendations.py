"""External tool suggestions used only when local analysis reaches a limit."""

CYBERCHEF_URL = "https://gchq.github.io/CyberChef/"

TOOL_BY_PROBLEM = {
    "encoding": ("CyberChef", CYBERCHEF_URL),
    "crypto": ("SageMath", "https://www.sagemath.org/"),
    "metadata": ("ExifTool", "https://exiftool.org/"),
    "steganography": ("zsteg", "https://github.com/zed-0xff/zsteg"),
    "archive": ("Binwalk", "https://github.com/ReFirmLabs/binwalk"),
    "pcap": ("Wireshark", "https://www.wireshark.org/"),
    "memory": ("Volatility 3", "https://github.com/volatilityfoundation/volatility3"),
    "reverse": ("Ghidra", "https://ghidra-sre.org/"),
    "android": ("JADX", "https://github.com/skylot/jadx"),
    "web": ("Burp Suite Community Edition", "https://portswigger.net/burp/communitydownload"),
}

CYBERCHEF_OPERATIONS = {
    "base64": "From Base64", "base32": "From Base32", "hex": "From Hex",
    "url": "URL Decode", "rot13": "ROT13", "caesar": "ROT13 or ROT47",
    "xor": "XOR Brute Force", "binary": "From Binary", "decimal": "From Decimal",
    "ascii": "From Charcode", "morse": "From Morse Code", "html": "HTML Entity Decode",
    "unicode": "Unescape Unicode Characters", "gzip": "Gunzip", "zlib": "Zlib Inflate",
    "jwt": "Parse JWT",
}


def recommend(problem: str) -> dict[str, str] | None:
    item = TOOL_BY_PROBLEM.get(problem.lower())
    if item is None:
        return None
    return {"tool": item[0], "url": item[1]}


def cyberchef_operation(kind: str) -> str | None:
    return CYBERCHEF_OPERATIONS.get(kind.lower())
