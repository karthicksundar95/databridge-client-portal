import os
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

endpoint = os.environ["S3_ENDPOINT"]
client = boto3.client(
    "s3",
    endpoint_url=endpoint,
    region_name=os.getenv("S3_REGION", "us-east-1"),
    aws_access_key_id=os.environ["S3_ACCESS_KEY"],
    aws_secret_access_key=os.environ["S3_SECRET_KEY"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)

for attempt in range(30):
    try:
        client.list_buckets()
        break
    except EndpointConnectionError:
        if attempt == 29:
            raise
        time.sleep(2)

existing = {bucket["Name"] for bucket in client.list_buckets()["Buckets"]}
for bucket in (os.environ["UPLOAD_BUCKET"], os.environ["DELIVERABLE_BUCKET"]):
    if bucket not in existing:
        try:
            client.create_bucket(Bucket=bucket)
        except ClientError as error:
            if error.response["Error"]["Code"] not in {"BucketAlreadyExists", "BucketAlreadyOwnedByYou"}:
                raise

print("Private local buckets are ready")
