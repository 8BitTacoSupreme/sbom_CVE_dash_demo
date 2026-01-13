#!/usr/bin/env python3
"""
SCA Orchestrator Service

Consumes SBOM scan requests from Kafka and fans out to multiple SCA tools
(Snyk, FOSSA, SonarQube) in parallel. BlackDuck and Sonatype coming soon.

Results are published to both:
- Unified topic: sca_scan_responses (all tools)
- Per-tool topics: sca_snyk_responses, sca_fossa_responses, etc.

Also writes results to PostgreSQL for Grafana dashboards.
"""

import asyncio
import json
import os
import sys
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import psycopg2
from psycopg2.extras import Json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients import (
    SnykClient,
    BlackDuckClient,
    SonarQubeClient,
    SonatypeClient,
    FOSSAClient,
    SCAResponse
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Configuration
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
REQUEST_TOPIC = "sca_scan_requests"
UNIFIED_RESPONSE_TOPIC = "sca_scan_responses"
CONSUMER_GROUP = "sca-orchestrator"

# Per-tool response topics
TOOL_TOPICS = {
    "snyk": "sca_snyk_responses",
    "fossa": "sca_fossa_responses",
    "blackduck": "sca_blackduck_responses",
    "sonar": "sca_sonar_responses",
    "sonatype": "sca_sonatype_responses"
}

# PostgreSQL config
PG_HOST = os.environ.get("POSTGRES_HOST", "localhost")
PG_PORT = os.environ.get("POSTGRES_PORT", "5432")
PG_DB = os.environ.get("POSTGRES_DB", "sca_demo")
PG_USER = os.environ.get("POSTGRES_USER", "sca")
PG_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "sca_password")


class SCAOrchestrator:
    """
    Orchestrates SBOM scanning across multiple SCA tools.

    Consumes from sca_scan_requests, fans out to configured tools,
    and publishes results to Kafka and PostgreSQL.
    """

    def __init__(self):
        self.consumer: Optional[KafkaConsumer] = None
        self.producer: Optional[KafkaProducer] = None
        self.pg_conn = None

        # Initialize SCA clients
        self.clients = {
            "snyk": SnykClient(),
            "fossa": FOSSAClient(),
            "sonar": SonarQubeClient(),
            "blackduck": BlackDuckClient(),
            "sonatype": SonatypeClient()
        }

        # Track configured tools
        self.configured_tools = [
            name for name, client in self.clients.items()
            if client.is_configured
        ]
        logger.info(f"Configured SCA tools: {self.configured_tools or 'none'}")

    def connect_kafka(self, max_retries: int = 30, retry_delay: int = 5):
        """Connect to Kafka with retries."""
        for attempt in range(max_retries):
            try:
                self.consumer = KafkaConsumer(
                    REQUEST_TOPIC,
                    bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
                    group_id=CONSUMER_GROUP,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    key_deserializer=lambda k: k.decode("utf-8") if k else None,
                    auto_offset_reset="earliest",
                    enable_auto_commit=True
                )

                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    acks="all",
                    retries=3
                )

                logger.info(f"Connected to Kafka at {KAFKA_BOOTSTRAP}")
                return

            except Exception as e:
                logger.warning(f"Kafka connection attempt {attempt + 1}/{max_retries}: {e}")
                time.sleep(retry_delay)

        raise ConnectionError(f"Failed to connect to Kafka after {max_retries} attempts")

    def connect_postgres(self, max_retries: int = 30, retry_delay: int = 5):
        """Connect to PostgreSQL with retries."""
        for attempt in range(max_retries):
            try:
                self.pg_conn = psycopg2.connect(
                    host=PG_HOST,
                    port=PG_PORT,
                    dbname=PG_DB,
                    user=PG_USER,
                    password=PG_PASSWORD
                )
                self.pg_conn.autocommit = True
                logger.info(f"Connected to PostgreSQL at {PG_HOST}:{PG_PORT}")
                return

            except Exception as e:
                logger.warning(f"PostgreSQL connection attempt {attempt + 1}/{max_retries}: {e}")
                time.sleep(retry_delay)

        raise ConnectionError(f"Failed to connect to PostgreSQL after {max_retries} attempts")

    async def process_request(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process an SCA scan request.

        Fans out to all requested tools in parallel.
        """
        sbom_key = request.get("sbom_key", "unknown")
        environment_id = request.get("environment_id", "unknown")
        sbom = request.get("sbom", {})
        requested_tools = request.get("tools", list(self.clients.keys()))
        submitted_at = request.get("requested_at", datetime.now(timezone.utc).isoformat())

        logger.info(f"Processing request {sbom_key} for tools: {requested_tools}")

        # Filter to only configured tools
        tools_to_run = [
            tool for tool in requested_tools
            if tool in self.configured_tools
        ]

        if not tools_to_run:
            logger.warning(f"No configured tools available for request {sbom_key}")
            # Return error responses for all requested tools
            return [
                self._create_error_response(
                    sbom_key, environment_id, tool, submitted_at,
                    f"{tool} not configured"
                )
                for tool in requested_tools
            ]

        # Fan out to all tools in parallel
        tasks = [
            self._scan_with_tool(tool, sbom, sbom_key, environment_id, submitted_at)
            for tool in tools_to_run
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert results to response dicts
        responses = []
        for i, result in enumerate(results):
            tool = tools_to_run[i]
            if isinstance(result, Exception):
                logger.error(f"Error from {tool}: {result}")
                responses.append(self._create_error_response(
                    sbom_key, environment_id, tool, submitted_at, str(result)
                ))
            else:
                responses.append(result)

        return responses

    async def _scan_with_tool(
        self,
        tool: str,
        sbom: dict,
        sbom_key: str,
        environment_id: str,
        submitted_at: str
    ) -> Dict[str, Any]:
        """Run scan with a specific tool and format response."""
        client = self.clients[tool]
        logger.info(f"[{tool}] Starting scan for {sbom_key}")

        try:
            response = await client.scan_sbom(sbom)
            completed_at = datetime.now(timezone.utc).isoformat()

            return {
                "sbom_key": sbom_key,
                "environment_id": environment_id,
                "source": tool,
                "scan_id": response.scan_id,
                "status": response.status,
                "submitted_at": submitted_at,
                "completed_at": completed_at,
                "latency_ms": response.latency_ms,
                "error_message": response.error_message,
                "results": {
                    "summary": {
                        "total_packages": response.total_packages,
                        "packages_with_issues": response.packages_with_issues,
                        "critical": response.critical,
                        "high": response.high,
                        "medium": response.medium,
                        "low": response.low
                    },
                    "vulnerabilities": [v.to_dict() for v in response.vulnerabilities]
                }
            }

        except Exception as e:
            logger.error(f"[{tool}] Scan failed: {e}")
            return self._create_error_response(
                sbom_key, environment_id, tool, submitted_at, str(e)
            )

    def _create_error_response(
        self,
        sbom_key: str,
        environment_id: str,
        tool: str,
        submitted_at: str,
        error: str
    ) -> Dict[str, Any]:
        """Create an error response for a failed scan."""
        return {
            "sbom_key": sbom_key,
            "environment_id": environment_id,
            "source": tool,
            "scan_id": "error",
            "status": "failed",
            "submitted_at": submitted_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "latency_ms": 0,
            "error_message": error,
            "results": {
                "summary": {
                    "total_packages": 0,
                    "packages_with_issues": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "vulnerabilities": []
            }
        }

    def publish_response(self, response: Dict[str, Any]):
        """Publish response to Kafka topics."""
        sbom_key = response.get("sbom_key")
        source = response.get("source")

        # Publish to unified topic
        try:
            self.producer.send(UNIFIED_RESPONSE_TOPIC, key=sbom_key, value=response)
            logger.debug(f"Published to {UNIFIED_RESPONSE_TOPIC}")
        except KafkaError as e:
            logger.error(f"Failed to publish to {UNIFIED_RESPONSE_TOPIC}: {e}")

        # Publish to per-tool topic
        tool_topic = TOOL_TOPICS.get(source)
        if tool_topic:
            try:
                self.producer.send(tool_topic, key=sbom_key, value=response)
                logger.debug(f"Published to {tool_topic}")
            except KafkaError as e:
                logger.error(f"Failed to publish to {tool_topic}: {e}")

        self.producer.flush()

    def save_to_postgres(self, response: Dict[str, Any]):
        """Save scan result to PostgreSQL."""
        if not self.pg_conn:
            logger.warning("PostgreSQL not connected, skipping save")
            return

        try:
            summary = response.get("results", {}).get("summary", {})

            with self.pg_conn.cursor() as cursor:
                # Insert scan result
                cursor.execute("""
                    INSERT INTO sca_scan_results (
                        sbom_key, environment_id, source, scan_id, status,
                        submitted_at, completed_at, latency_ms,
                        total_packages, packages_with_issues,
                        critical_count, high_count, medium_count, low_count,
                        error_message, raw_response
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s, %s, %s,
                        %s, %s
                    ) RETURNING id
                """, (
                    response.get("sbom_key"),
                    response.get("environment_id"),
                    response.get("source"),
                    response.get("scan_id"),
                    response.get("status"),
                    response.get("submitted_at"),
                    response.get("completed_at"),
                    response.get("latency_ms"),
                    summary.get("total_packages", 0),
                    summary.get("packages_with_issues", 0),
                    summary.get("critical", 0),
                    summary.get("high", 0),
                    summary.get("medium", 0),
                    summary.get("low", 0),
                    response.get("error_message"),
                    Json(response)
                ))

                result_id = cursor.fetchone()[0]

                # Insert vulnerabilities
                vulnerabilities = response.get("results", {}).get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cursor.execute("""
                        INSERT INTO sca_tool_vulnerabilities (
                            scan_result_id, sbom_key, source,
                            cve_id, source_vuln_id,
                            package_name, package_version, purl,
                            severity, cvss_score, epss_score, remediation
                        ) VALUES (
                            %s, %s, %s,
                            %s, %s,
                            %s, %s, %s,
                            %s, %s, %s, %s
                        )
                    """, (
                        result_id,
                        response.get("sbom_key"),
                        response.get("source"),
                        vuln.get("cve_id"),
                        vuln.get("source_id"),
                        vuln.get("package"),
                        vuln.get("version"),
                        vuln.get("purl"),
                        vuln.get("severity"),
                        vuln.get("cvss_score"),
                        vuln.get("epss_score"),
                        vuln.get("remediation")
                    ))

            logger.debug(f"Saved result {result_id} to PostgreSQL")

        except Exception as e:
            logger.error(f"Failed to save to PostgreSQL: {e}")

    def run(self):
        """Main consumer loop."""
        logger.info("Starting SCA Orchestrator...")

        self.connect_kafka()
        self.connect_postgres()

        logger.info(f"Consuming from topic: {REQUEST_TOPIC}")

        try:
            for message in self.consumer:
                try:
                    request = message.value
                    sbom_key = request.get("sbom_key", "unknown")
                    logger.info(f"Received request: {sbom_key}")

                    # Run async processing
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        responses = loop.run_until_complete(self.process_request(request))
                    finally:
                        loop.close()

                    # Publish and save each response
                    for response in responses:
                        self.publish_response(response)
                        self.save_to_postgres(response)

                    logger.info(f"Completed request: {sbom_key} ({len(responses)} responses)")

                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    import traceback
                    traceback.print_exc()

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.consumer:
                self.consumer.close()
            if self.producer:
                self.producer.close()
            if self.pg_conn:
                self.pg_conn.close()


def main():
    orchestrator = SCAOrchestrator()
    orchestrator.run()


if __name__ == "__main__":
    main()
