"""
Splunk Consumer for SCA Vulnerability Data

Consumes vulnerability matches from Kafka and sends to Splunk via HTTP Event Collector (HEC).
This provides an "also works with" alternative to Elasticsearch/Kibana.
"""

import json
import os
import time
import logging
import urllib3
from datetime import datetime
from typing import Dict, Any, Optional

import requests
from kafka import KafkaConsumer

# Disable SSL warnings for local docker setup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SplunkConsumer:
    """
    Consumes vulnerability_matches from Kafka and sends to Splunk HEC.

    Environment Variables:
        KAFKA_BOOTSTRAP_SERVERS: Kafka broker addresses
        SPLUNK_HEC_URL: Splunk HTTP Event Collector URL (e.g., https://splunk:8088)
        SPLUNK_HEC_TOKEN: HEC authentication token
        SPLUNK_INDEX: Target index name (default: sca_vulnerabilities)
        SPLUNK_VERIFY_SSL: Whether to verify SSL certificates (default: false)
    """

    def __init__(
        self,
        kafka_bootstrap: str,
        hec_url: str,
        hec_token: str,
        index: str = "sca_vulnerabilities",
        verify_ssl: bool = False,
        consumer_group: str = "splunk-indexer"
    ):
        self.kafka_bootstrap = kafka_bootstrap
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.index = index
        self.verify_ssl = verify_ssl
        self.consumer_group = consumer_group

        self.consumer: Optional[KafkaConsumer] = None
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Splunk {hec_token}',
            'Content-Type': 'application/json'
        })

    def connect(self, max_retries: int = 30, retry_delay: int = 5):
        """Connect to Kafka and verify Splunk HEC connectivity."""
        # Verify Splunk HEC
        for attempt in range(max_retries):
            try:
                resp = self.session.get(
                    f"{self.hec_url}/services/collector/health",
                    verify=self.verify_ssl,
                    timeout=10
                )
                if resp.status_code in [200, 400]:  # 400 is OK for health check
                    logger.info(f"Connected to Splunk HEC at {self.hec_url}")
                    break
            except Exception as e:
                logger.warning(f"Splunk HEC connection attempt {attempt + 1}/{max_retries}: {e}")
                time.sleep(retry_delay)
        else:
            raise ConnectionError(f"Failed to connect to Splunk HEC after {max_retries} attempts")

        # Connect to Kafka
        for attempt in range(max_retries):
            try:
                self.consumer = KafkaConsumer(
                    'vulnerability_matches',
                    bootstrap_servers=self.kafka_bootstrap.split(','),
                    group_id=self.consumer_group,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='earliest',
                    enable_auto_commit=True
                )
                logger.info(f"Connected to Kafka at {self.kafka_bootstrap}")
                return
            except Exception as e:
                logger.warning(f"Kafka connection attempt {attempt + 1}/{max_retries}: {e}")
                time.sleep(retry_delay)

        raise ConnectionError(f"Failed to connect to Kafka after {max_retries} attempts")

    def _parse_timestamp(self, timestamp: Any) -> float:
        """Parse timestamp to epoch seconds for Splunk."""
        if timestamp is None:
            return time.time()

        if isinstance(timestamp, (int, float)):
            return float(timestamp)

        if isinstance(timestamp, str):
            try:
                # Try ISO format
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.timestamp()
            except ValueError:
                pass

        return time.time()

    def transform(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform Kafka message to Splunk HEC event format.

        Splunk HEC format:
        {
            "time": <epoch>,
            "host": "hostname",
            "source": "source_name",
            "sourcetype": "custom_sourcetype",
            "index": "target_index",
            "event": { ... actual data ... }
        }
        """
        return {
            'time': self._parse_timestamp(message.get('detected_at')),
            'host': 'flox-sca-demo',
            'source': 'vulnerability_matches',
            'sourcetype': 'sca:vulnerability',
            'index': self.index,
            'event': {
                # Identity
                'match_id': message.get('match_id'),
                'cve_id': message.get('cve_id'),

                # Package info
                'package_name': message.get('package_name'),
                'package_version': message.get('package_version'),
                'purl': message.get('purl') or message.get('package_purl'),

                # Environment
                'environment': message.get('environment') or message.get('environment_id'),
                'producer': message.get('producer'),

                # Severity and scoring
                'severity': message.get('severity', 'unknown'),
                'cvss_score': message.get('cvss_score'),
                'epss_score': message.get('epss_score'),
                'epss_percentile': message.get('epss_percentile'),
                'risk_score': message.get('risk_score'),

                # Tiering
                'alert_tier': message.get('alert_tier', 3),
                'tier_reason': message.get('tier_reason'),

                # KEV status
                'cisa_kev': message.get('cisa_kev', False),
                'kev_date_added': message.get('kev_date_added'),

                # VEX status
                'vex_status': message.get('vex_status', 'affected'),
                'vex_reason': message.get('vex_reason'),

                # Additional context
                'cwe_ids': message.get('cwe_ids', []),
                'description': message.get('description', ''),
                'status': message.get('status', 'active'),
                'affected_versions': message.get('affected_versions', []),
                'references': message.get('references', []),

                # Timestamps
                'detected_at': message.get('detected_at'),
                'cve_published_at': message.get('cve_published_at')
            }
        }

    def send_to_splunk(self, event: Dict[str, Any]) -> bool:
        """Send event to Splunk HEC."""
        try:
            resp = self.session.post(
                f"{self.hec_url}/services/collector/event",
                json=event,
                verify=self.verify_ssl,
                timeout=30
            )

            if resp.status_code == 200:
                return True
            else:
                logger.error(f"Splunk HEC error: {resp.status_code} - {resp.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False

    def run(self):
        """Main consumer loop."""
        logger.info("Starting Splunk consumer...")
        self.connect()

        indexed_count = 0
        error_count = 0

        try:
            for message in self.consumer:
                try:
                    # Transform message
                    event = self.transform(message.value)

                    # Send to Splunk
                    if self.send_to_splunk(event):
                        indexed_count += 1
                        if indexed_count % 100 == 0:
                            logger.info(f"Sent {indexed_count} events to Splunk")
                    else:
                        error_count += 1

                except Exception as e:
                    error_count += 1
                    logger.error(f"Failed to process message: {e}")
                    if error_count > 100:
                        logger.error("Too many errors, exiting")
                        break

        except KeyboardInterrupt:
            logger.info("Shutting down consumer...")
        finally:
            if self.consumer:
                self.consumer.close()
            logger.info(f"Consumer stopped. Total sent: {indexed_count}, errors: {error_count}")


def main():
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    hec_url = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088")
    hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    index = os.environ.get("SPLUNK_INDEX", "sca_vulnerabilities")
    verify_ssl = os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    if not hec_token:
        logger.error("SPLUNK_HEC_TOKEN environment variable is required")
        return

    consumer = SplunkConsumer(
        kafka_bootstrap=kafka_bootstrap,
        hec_url=hec_url,
        hec_token=hec_token,
        index=index,
        verify_ssl=verify_ssl
    )
    consumer.run()


if __name__ == "__main__":
    main()
