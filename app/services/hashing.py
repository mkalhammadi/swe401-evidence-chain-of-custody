"""HashService - SHA-256 hashing of evidence files in fixed-size chunks."""
import hashlib

DEFAULT_CHUNK = 64 * 1024


def sha256_stream(stream, chunk_size=DEFAULT_CHUNK, sink=None):
    """Hash a binary stream chunk by chunk.

    If `sink` (a writable binary file) is given, each chunk is also written to it,
    so a file can be stored and hashed in a single pass without loading it into memory.
    Returns (hex_digest, total_bytes).
    """
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
        total += len(chunk)
        if sink is not None:
            sink.write(chunk)
    return h.hexdigest(), total


def sha256_file(path, chunk_size=DEFAULT_CHUNK):
    with open(path, "rb") as fh:
        digest, _ = sha256_stream(fh, chunk_size)
    return digest


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
