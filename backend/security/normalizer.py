import html
import re
import urllib.parse


def normalize(text: str) -> str:

    if not text:
        return ""

    # URL Decode
    text = urllib.parse.unquote(text)

    # HTML Entity Decode
    text = html.unescape(text)

    # Lowercase
    text = text.lower()

    # Remove extra whitespace
    text = re.sub(r"\s+", " ", text)

    # Strip leading/trailing spaces
    text = text.strip()

    return text
