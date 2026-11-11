# DataBridge client portal service

Python/FastAPI service for client portal accounts, profiles, submissions, and private object-storage upload/download authorization.

Client accounts are created through public signup and authenticated with database-backed, revocable JWT sessions. Analyst and administrator accounts are provisioned with `scripts/create_user.py`; they cannot use client signup. File records are created only after the service verifies the uploaded object in private S3-compatible storage, with a 5 GB limit per direct upload. When an analyst opens a submission's file list, the service also discovers older upload objects that predate database file registration and safely registers them for download.

In AWS, the client service's IRSA role must allow `s3:ListBucket` on the private upload bucket, constrained with the `s3:prefix` condition to `submissions/*`, for legacy file discovery. Keep `s3:GetObject` and upload permissions scoped to the upload bucket's objects; do not make the bucket public.

Run locally with `uv run start` (port 8081). Database schema and local dependencies are provided by the DataBridge deployment repository's Docker Compose setup. Outside development, set `ENVIRONMENT` and provide a non-development `JWT_SECRET` of at least 32 characters.
