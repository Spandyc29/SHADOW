from services.virustotal import check_domain, check_hash, check_ip, check_url


class ThreatGateway:
    """
    Threat Intelligence Gateway

    Purpose:
        - Acts as a single entry point for all threat intelligence providers.
        - Routers and services should NEVER call VirusTotal directly.
        - Future providers (OTX, AbuseIPDB, Hybrid Analysis, etc.)
          will be added here without changing router logic.
    """

    @staticmethod
    async def lookup_indicator(
        indicator: str,
        indicator_type: str
    ) -> dict:
        """
        Lookup an indicator using the appropriate provider.

        Args:
            indicator (str): Hash/IP/URL/Domain
            indicator_type (str): hash | ip | url | domain

        Returns:
            dict: Raw provider response
        """

        indicator_type = indicator_type.lower()

        # -------------------------
        # HASH LOOKUP
        # -------------------------
        if indicator_type == "hash":
            return await check_hash(indicator)

        elif indicator_type == "ip":
            return await check_ip(indicator)

        elif indicator_type == "url":
            return await check_url(indicator)

        elif indicator_type == "domain":
            return await check_domain(indicator)

        else:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")
