#!/bin/bash

# KMS Keys are not generated because the application code handles this

# Apple keys table
awslocal dynamodb create-table \
    --table-name attestation-gateway-apple-keys \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1