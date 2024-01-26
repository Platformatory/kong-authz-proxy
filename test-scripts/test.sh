#!/bin/bash

KONG_API_URL="http://localhost:8000"
LISTENER_PATH="/authz"  # Replace with your actual path

SCOPE="request.query.foo"
OPERATOR="prefix"
VALUE="b"
EXP=3600  # Expiry in seconds

PAYLOAD="{\"scope\": \"$SCOPE\", \"operator\": \"$OPERATOR\", \"value\": \"$VALUE\", \"exp\": $EXP}"

curl -X POST "$KONG_API_URL$LISTENER_PATH" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD"

echo

