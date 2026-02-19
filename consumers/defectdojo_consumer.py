"""
DefectDojo Consumer for SCA Vulnerability Data

Consumes vulnerability matches from Kafka, batches them by environment_id,
builds CycloneDX SBOMs with embedded vulnerabilities, and imports to
DefectDojo via the reimport-scan API.

DefectDojo provides:
  - Remediation workflow (assign, track, close findings)
  - SLA compliance tracking (MTTR, overdue findings)
  - Deduplication across scans
  - JIRA/Slack/email integration for notifications

Integration pattern:
  vulnerability_matches (Kafka)
    -> batch by environment_id
    -> build CycloneDX 1.4 SBOM with vulnerabilities array
    -> POST /api/v2/reimport-scan/ (auto_create_context=true)
    -> DD creates/updates findings with hash-based dedup

DD data model mapping:
  Product Type = "Flox SCA"
  Product = environment_id
  Engagement = "Continuous Monitoring"
  Test = each reimport (timestamped)
  Finding = each CVE match
"""

import json
import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import defaultdict

from kafka import KafkaConsumer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import DefectDojo client - handle case where requests isn't available in container
try:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from clients.defectdojo_client import DefectDojoClient
except ImportError:
    DefectDojoClient = None
    logger.warning("DefectDojo client not available (missing requests?)")


class DefectDojoConsumer:
    """Consumes vulnerability_matches from Kafka, imports to DefectDojo."""

    def __init__(
        self,
        kafka_bootstrap: str,
        defectdojo_url: str,
        defectdojo_token: str,
        consumer_group: str = "defectdojo-importer",
        batch_size: int = 50,
        batch_timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ):
        self.kafka_bootstrap = kafka_bootstrap
        self.defectdojo_url = defectdojo_url
        self.defectdojo_token = defectdojo_token
        self.consumer_group = consumer_group
        self.batch_size = batch_size
        self.batch_timeout_seconds = batch_timeout_seconds
        self.verify_ssl = verify_ssl
        self.consumer: Optional[KafkaConsumer] = None
        self.dd_client: Optional[Any] = None

        # Batching state: environment_id -> list of matches
        self.batch: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.batch_start_time: float = time.time()

        # Stats
        self.total_consumed = 0
        self.total_imported = 0
        self.total_errors = 0

    def connect(self, max_retries: int = 30, retry_delay: int = 5):
        """Connect to Kafka and DefectDojo with retries."""
        # Connect to DefectDojo
        if DefectDojoClient is None:
            raise RuntimeError("DefectDojo client not available")

        self.dd_client = DefectDojoClient(
            base_url=self.defectdojo_url,
            api_token=self.defectdojo_token,
            verify_ssl=self.verify_ssl,
        )

        for attempt in range(max_retries):
            if self.dd_client.health_check():
                logger.info(f"Connected to DefectDojo at {self.defectdojo_url}")
                break
            logger.warning(f"DefectDojo connection attempt {attempt + 1}/{max_retries} failed")
            time.sleep(retry_delay)
        else:
            raise ConnectionError(f"Failed to connect to DefectDojo after {max_retries} attempts")

        # Connect to Kafka
        for attempt in range(max_retries):
            try:
                self.consumer = KafkaConsumer(
                    'vulnerability_matches',
                    bootstrap_servers=self.kafka_bootstrap.split(','),
                    group_id=self.consumer_group,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='earliest',
                    enable_auto_commit=True,
                )
                logger.info(f"Connected to Kafka at {self.kafka_bootstrap}")
                break
            except Exception as e:
                logger.warning(f"Kafka connection attempt {attempt + 1}/{max_retries} failed: {e}")
                time.sleep(retry_delay)
        else:
            raise ConnectionError(f"Failed to connect to Kafka after {max_retries} attempts")

    def flush_batch(self, environment_id: str):
        """Flush a batch of matches for an environment to DefectDojo."""
        matches = self.batch.pop(environment_id, [])
        if not matches:
            return

        logger.info(f"Flushing {len(matches)} findings for '{environment_id}' to DefectDojo")

        # Build CycloneDX SBOM with embedded vulnerabilities
        sbom = DefectDojoClient.build_cyclonedx_sbom(environment_id, matches)

        # Import to DefectDojo
        result = self.dd_client.reimport_scan(
            environment_id=environment_id,
            cyclonedx_sbom=sbom,
        )

        if result:
            self.total_imported += result.finding_count
            logger.info(
                f"  DefectDojo import: test={result.test_id}, "
                f"created={result.created}, closed={result.closed}, "
                f"reactivated={result.reactivated}, untouched={result.left_untouched}"
            )
        else:
            self.total_errors += 1
            logger.error(f"  DefectDojo import failed for '{environment_id}'")

    def flush_all_batches(self):
        """Flush all pending batches."""
        environments = list(self.batch.keys())
        for env_id in environments:
            self.flush_batch(env_id)
        self.batch_start_time = time.time()

    def should_flush(self) -> bool:
        """Check if any batch should be flushed (by size or timeout)."""
        # Check timeout
        if time.time() - self.batch_start_time > self.batch_timeout_seconds:
            return True
        # Check any batch exceeds size
        for matches in self.batch.values():
            if len(matches) >= self.batch_size:
                return True
        return False

    def run(self):
        """Main consumer loop."""
        logger.info("Starting DefectDojo consumer...")
        logger.info(f"  DefectDojo: {self.defectdojo_url}")
        logger.info(f"  Batch size: {self.batch_size}, timeout: {self.batch_timeout_seconds}s")

        self.connect()

        try:
            while True:
                # Poll with timeout to allow batch flushing
                messages = self.consumer.poll(timeout_ms=1000)

                for topic_partition, records in messages.items():
                    for record in records:
                        match = record.value
                        env_id = match.get('environment_id', 'unknown')

                        self.batch[env_id].append(match)
                        self.total_consumed += 1

                        if self.total_consumed % 100 == 0:
                            logger.info(f"Consumed {self.total_consumed} messages")

                # Check if we should flush
                if self.should_flush() and self.batch:
                    self.flush_all_batches()

        except KeyboardInterrupt:
            logger.info("Shutting down consumer...")
        finally:
            # Flush remaining
            if self.batch:
                logger.info("Flushing remaining batches...")
                self.flush_all_batches()
            if self.consumer:
                self.consumer.close()
            logger.info(
                f"Consumer stopped. Consumed: {self.total_consumed}, "
                f"imported: {self.total_imported}, errors: {self.total_errors}"
            )


def main():
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    defectdojo_url = os.environ.get("DEFECTDOJO_URL", "http://localhost:8443")
    defectdojo_token = os.environ.get("DEFECTDOJO_API_TOKEN", "")
    verify_ssl = os.environ.get("DEFECTDOJO_VERIFY_SSL", "true").lower() == "true"
    batch_size = int(os.environ.get("DEFECTDOJO_BATCH_SIZE", "50"))
    batch_timeout = int(os.environ.get("DEFECTDOJO_BATCH_TIMEOUT", "30"))

    if not defectdojo_token:
        logger.error("DEFECTDOJO_API_TOKEN is required. Set it in .env or environment.")
        logger.error("Get a token from DefectDojo: API v2 > Tokens")
        return

    consumer = DefectDojoConsumer(
        kafka_bootstrap=kafka_bootstrap,
        defectdojo_url=defectdojo_url,
        defectdojo_token=defectdojo_token,
        verify_ssl=verify_ssl,
        batch_size=batch_size,
        batch_timeout_seconds=batch_timeout,
    )
    consumer.run()


if __name__ == "__main__":
    main()
