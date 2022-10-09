### Auth Process Codex

    Get the master secret key.
    Make a new AES cipher block.
    Make a new GCM cipher block which returns an AEAD object.
    Verify the encrypted key’s length.
    Finally, “Open” the encrypted key by passing in nil for the destination, then the nonce which was prepended in the final key, then the actual encrypted key bytes (the latter part), and nil for extra data.
