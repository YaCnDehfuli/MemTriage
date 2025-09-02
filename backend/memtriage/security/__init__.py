"""Security utilities: input validation, DoS limits, and artifact sanitization.

Handling untrusted (potentially malicious) memory images is part of the design,
not an afterthought. Two rules run through this package:

1. Uploaded samples are NEVER executed. Memory images and dumped VAD regions are
   read as opaque bytes only.
2. Every string that originates from the dump is attacker-controlled. It is
   sanitized here before it is ever persisted into a report or rendered in the
   dashboard (stored-XSS from artifact metadata is a real risk).
"""
