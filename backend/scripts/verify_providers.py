import asyncio

from app.core.http_client import HTTPClient
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.threatfox_service import ThreatFoxService
from app.services.urlhaus_service import URLhausService
from app.services.virustotal_service import VirusTotalService


async def main() -> None:
    client = HTTPClient()
    try:
        virustotal, abuseipdb, threatfox, urlhaus = await asyncio.gather(
            VirusTotalService(client).lookup_hash("44d88612fea8a8f36de82e1278abb02f"),
            AbuseIPDBService(client).lookup_ip("8.8.8.8"),
            ThreatFoxService(client).lookup_hash("44d88612fea8a8f36de82e1278abb02f"),
            URLhausService(client).lookup_host("urlhaus.abuse.ch"),
        )
        print(f"VIRUSTOTAL_STATUS={virustotal.status}")
        print(f"VIRUSTOTAL_MALICIOUS={int((virustotal.data or {}).get('malicious', 0))}")
        print(f"ABUSEIPDB_STATUS={abuseipdb.status}")
        print(f"THREATFOX_STATUS={threatfox.status}")
        print(f"THREATFOX_MATCH={bool((threatfox.data or {}).get('listed', False))}")
        print(f"URLHAUS_STATUS={urlhaus.status}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
