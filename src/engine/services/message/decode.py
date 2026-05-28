"""Message decoding utilities — zstd decompression and sender extraction.

This module provides the first two steps of the message pipeline:
1. decompress_content: decompress WeChat 4.x zstd-compressed message content
2. split_sender_prefix: extract sender wxid from group message prefix
"""

try:
    import zstandard as zstd
    _ZSTD_CTX = zstd.ZstdDecompressor()
except ImportError:
    _ZSTD_CTX = None

# WeChat 4.x zstd compression magic — zstd frame header
_ZSTD_MAGIC = b'\x28\xb5\x2f\xfd'


def decompress_content(raw_content: bytes) -> bytes:
    """Decompress WeChat 4.x zstd-compressed message content.

    Checks for the zstd frame magic bytes (\\x28\\xb5\\x2f\\xfd) and
    decompresses if present. Passes through non-compressed content unchanged.

    Args:
        raw_content: Raw message content bytes, or None.

    Returns:
        Decompressed bytes if input had zstd magic and decompression succeeded,
        original bytes if no zstd magic was detected,
        or None if input is None or decompression failed.
    """
    if raw_content is None:
        return None
    if len(raw_content) < 4 or raw_content[:4] != _ZSTD_MAGIC:
        return raw_content
    if _ZSTD_CTX is None:
        return None
    try:
        return _ZSTD_CTX.decompress(raw_content, max_output_size=50 * 1024 * 1024)
    except Exception:
        return None


def split_sender_prefix(raw: str, is_group: bool, is_sender: bool) -> tuple:
    """Split sender prefix from group message content.

    For group messages where the current user is not the sender, extracts
    the sender's wxid from the "sender:\\ncontent" prefix that WeChat prepends.

    Args:
        raw: The raw message content string.
        is_group: Whether the chat is a group chat.
        is_sender: Whether the current user sent the message.

    Returns:
        Tuple of (sender, body). If a prefix was found, sender is the raw
        sender prefix text and body is the remaining content. Otherwise
        sender is an empty string and body is the full raw string.
    """
    if is_group and not is_sender and raw and ':\n' in raw[:100]:
        parts = raw.split(':\n', 1)
        return (parts[0], parts[1])
    return ('', raw)
