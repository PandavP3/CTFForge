"""Candidate patterns; matches are only candidates until syntax validation."""
import re

URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/?^`{|}~-]+@[\w.-]+\.[A-Za-z\u0080-\uffff]{2,}(?![\w-])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
DOMAIN = re.compile(r"(?<![\w.-])(?:[\w\u0080-\uffff](?:[\w\u0080-\uffff-]{0,61}[\w\u0080-\uffff])?\.)+[\w\u0080-\uffff-]{2,63}(?![\w-])", re.IGNORECASE)

TRAILING_URL_PUNCTUATION = ".,;:!?\"'`"
LIKELY_FILE_SUFFIXES = frozenset({
    "bin", "cfg", "conf", "dat", "dll", "doc", "docx", "exe", "gif", "gz",
    "ico", "ini", "jpeg", "jpg", "json", "log", "pdf", "png", "rar", "so",
    "svg", "sys", "tar", "txt", "xml", "yaml", "yml", "zip",
})

