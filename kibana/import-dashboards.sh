#!/bin/bash
# Wait for Kibana and import saved objects

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
MAX_RETRIES=60
RETRY_INTERVAL=5

echo "Waiting for Kibana to be ready..."
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s "$KIBANA_URL/api/status" | grep -q '"overall":{"level":"available"'; then
        echo "Kibana is ready!"
        break
    fi
    echo "  Attempt $i/$MAX_RETRIES - Kibana not ready yet..."
    sleep $RETRY_INTERVAL
done

# Import saved objects (dashboards, index patterns, visualizations)
echo "Importing dashboards..."
curl -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form file=@/dashboards/sca_investigation.ndjson

echo "Dashboard import complete!"
