#!/bin/bash

# KMS Keys
# while creating keys is delegated to the application code, we create this key for quasi-unit tests of kms_jws module
## code above creates the following ECC key with curve `secp256r1` for integration tests
awslocal kms create-key --region eu-central-1 --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 --tags '[{"TagKey":"_custom_id_","TagValue":"c7956b9c-5235-4e8e-bb35-7310fb80f4ca"}]'

# Apple keys table
awslocal dynamodb create-table \
    --table-name attestation-gateway-apple-keys \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --billing-mode PAY_PER_REQUEST \
    --region eu-central-1

# Kinesis stream
awslocal kinesis create-stream --region us-west-1 --stream-name attestation-gateway-data-reports --shard-count 1