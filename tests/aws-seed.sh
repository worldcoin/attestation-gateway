#!/bin/bash

## ONLY FOR TESTING PURPOSES
## code above creates the following ECC key with curve `secp256r1` for integration tests
awslocal kms create-key --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256 --tags '[{"TagKey":"_custom_id_","TagValue":"c7956b9c-5235-4e8e-bb35-7310fb80f4ca"}]'

# key alias is defined in src/utils.rs
awslocal kms create-alias --alias-name alias/attestation-gateway-primary --target-key-id $(awslocal kms list-keys --query 'Keys[0].KeyId' --output text)


# Apple keys table
awslocal dynamodb create-table \
    --table-name attestation-gateway-apple-keys \
    --key-schema AttributeName=key_id,KeyType=HASH \
    --attribute-definitions AttributeName=key_id,AttributeType=S \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1