"""
Elasticsearch Consumer for SCA Vulnerability Data

Consumes vulnerability matches from Kafka and indexes to Elasticsearch
for investigation workflows and compliance reporting in Kibana.
"""

import json
import os
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from kafka import KafkaConsumer
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ElasticsearchConsumer:
    """Consumes vulnerability_matches from Kafka, indexes to Elasticsearch."""

    INDEX_MAPPING = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.mapping.total_fields.limit": 2000
        },
        "mappings": {
            "properties": {
                "match_id": {"type": "keyword"},
                "cve_id": {"type": "keyword"},
                "package_name": {"type": "keyword"},
                "package_version": {"type": "keyword"},
                "purl": {"type": "keyword"},
                "environment": {"type": "keyword"},
                "producer": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "cvss_score": {"type": "float"},
                "cisa_kev": {"type": "boolean"},
                "kev_date_added": {"type": "date"},
                "vex_status": {"type": "keyword"},
                "vex_reason": {"type": "keyword"},
                "cwe_ids": {"type": "keyword"},
                "description": {"type": "text", "analyzer": "standard"},
                "detected_at": {"type": "date"},
                "cve_published_at": {"type": "date"},
                "detection_latency_hours": {"type": "float"},
                "status": {"type": "keyword"},
                "affected_versions": {"type": "text"},
                "references": {"type": "nested", "properties": {
                    "url": {"type": "keyword"},
                    "source": {"type": "keyword"}
                }},
                "epss_score": {"type": "float"},
                "epss_percentile": {"type": "float"},
                "risk_score": {"type": "float"},
                "alert_tier": {"type": "integer"},
                "tier_reason": {"type": "keyword"}
            }
        }
    }

    def __init__(
        self,
        kafka_bootstrap: str,
        es_host: str,
        index_name: str = "vulnerability-matches",
        consumer_group: str = "es-indexer"
    ):
        self.kafka_bootstrap = kafka_bootstrap
        self.es_host = es_host
        self.index_name = index_name
        self.consumer_group = consumer_group
        self.consumer: Optional[KafkaConsumer] = None
        self.es: Optional[Elasticsearch] = None

    def connect(self, max_retries: int = 30, retry_delay: int = 5):
        """Connect to Kafka and Elasticsearch with retries."""
        # Connect to Elasticsearch
        for attempt in range(max_retries):
            try:
                self.es = Elasticsearch([self.es_host])
                # Use cluster health check instead of ping (more reliable for ES 8.x)
                info = self.es.info()
                logger.info(f"Connected to Elasticsearch at {self.es_host} (version {info['version']['number']})")
                break
            except Exception as e:
                logger.warning(f"ES connection attempt {attempt + 1}/{max_retries} failed: {e}")
                time.sleep(retry_delay)
        else:
            raise ConnectionError(f"Failed to connect to Elasticsearch after {max_retries} attempts")

        # Create index if not exists
        self.create_index()

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
                break
            except Exception as e:
                logger.warning(f"Kafka connection attempt {attempt + 1}/{max_retries} failed: {e}")
                time.sleep(retry_delay)
        else:
            raise ConnectionError(f"Failed to connect to Kafka after {max_retries} attempts")

    def create_index(self):
        """Create Elasticsearch index with proper mappings."""
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(index=self.index_name, body=self.INDEX_MAPPING)
            logger.info(f"Created index: {self.index_name}")
        else:
            logger.info(f"Index {self.index_name} already exists")

    def transform(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Kafka message to Elasticsearch document."""
        doc = {
            "match_id": message.get("match_id"),
            "cve_id": message.get("cve_id"),
            "package_name": message.get("package_name"),
            "package_version": message.get("package_version"),
            "purl": message.get("purl") or message.get("package_purl"),
            "environment": message.get("environment") or message.get("environment_id"),
            "producer": message.get("producer"),
            "severity": message.get("severity", "unknown"),
            "cvss_score": message.get("cvss_score"),
            "cisa_kev": message.get("cisa_kev", False),
            "kev_date_added": message.get("kev_date_added"),
            "vex_status": message.get("vex_status", "affected"),
            "vex_reason": message.get("vex_reason"),
            "cwe_ids": message.get("cwe_ids", []),
            "description": message.get("description", ""),
            "status": message.get("status", "active"),
            "affected_versions": json.dumps(message.get("affected_versions", [])),
            "references": message.get("references", []),
            "epss_score": message.get("epss_score"),
            "epss_percentile": message.get("epss_percentile"),
            "risk_score": message.get("risk_score"),
            "alert_tier": message.get("alert_tier", 3),
            "tier_reason": message.get("tier_reason")
        }

        # Parse timestamps
        detected_at = message.get("detected_at")
        cve_published_at = message.get("cve_published_at")

        if detected_at:
            try:
                if isinstance(detected_at, str):
                    doc["detected_at"] = detected_at
                else:
                    doc["detected_at"] = datetime.fromtimestamp(detected_at).isoformat()
            except:
                doc["detected_at"] = datetime.utcnow().isoformat()
        else:
            doc["detected_at"] = datetime.utcnow().isoformat()

        if cve_published_at:
            try:
                if isinstance(cve_published_at, str):
                    doc["cve_published_at"] = cve_published_at
                else:
                    doc["cve_published_at"] = datetime.fromtimestamp(cve_published_at).isoformat()
            except:
                pass

        # Calculate detection latency
        if doc.get("detected_at") and doc.get("cve_published_at"):
            try:
                detected = datetime.fromisoformat(doc["detected_at"].replace('Z', '+00:00').replace('+00:00', ''))
                published = datetime.fromisoformat(doc["cve_published_at"].replace('Z', '+00:00').replace('+00:00', ''))
                latency_hours = (detected - published).total_seconds() / 3600
                if latency_hours > 0:
                    doc["detection_latency_hours"] = round(latency_hours, 2)
            except Exception as e:
                logger.debug(f"Could not calculate detection latency: {e}")

        return doc

    def run(self):
        """Main consumer loop."""
        logger.info("Starting Elasticsearch consumer...")
        self.connect()

        indexed_count = 0
        error_count = 0

        try:
            for message in self.consumer:
                try:
                    doc = self.transform(message.value)
                    doc_id = doc.get("match_id") or f"{doc['cve_id']}_{doc['purl']}_{doc['environment']}"

                    self.es.index(
                        index=self.index_name,
                        id=doc_id,
                        document=doc
                    )
                    indexed_count += 1

                    if indexed_count % 100 == 0:
                        logger.info(f"Indexed {indexed_count} documents")

                except Exception as e:
                    error_count += 1
                    logger.error(f"Failed to index message: {e}")
                    if error_count > 100:
                        logger.error("Too many errors, exiting")
                        break

        except KeyboardInterrupt:
            logger.info("Shutting down consumer...")
        finally:
            if self.consumer:
                self.consumer.close()
            logger.info(f"Consumer stopped. Total indexed: {indexed_count}, errors: {error_count}")


def main():
    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    es_host = os.environ.get("ELASTICSEARCH_HOST", "http://localhost:9200")
    index_name = os.environ.get("ES_INDEX_NAME", "vulnerability-matches")

    consumer = ElasticsearchConsumer(
        kafka_bootstrap=kafka_bootstrap,
        es_host=es_host,
        index_name=index_name
    )
    consumer.run()


if __name__ == "__main__":
    main()
