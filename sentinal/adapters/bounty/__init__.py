"""Generic published bounty-policy tracking.

Wraps any endpoint that returns a normalised bounty policy, so it owns no site of its
own and declares no ``url_hosts``.
"""

from __future__ import annotations
