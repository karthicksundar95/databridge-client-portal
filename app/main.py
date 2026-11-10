import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import bcrypt
import boto3
import jwt
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://databridge:databridge_dev@localhost:5432/databridge")
JWT_SECRET = os.getenv("JWT_SECRET", "development-only-secret-change-me")
JWT_ALGORITHM = "HS256"
CORS_ORIGIN = [item.strip() for item in os.getenv("CORS_ORIGIN", "").split(",") if item]
UPLOAD_BUCKET = os.getenv("UPLOAD_BUCKET", "databridge-uploads")
DELIVERABLE_BUCKET = os.getenv("DELIVERABLE_BUCKET", "databridge-deliverables")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
s3_config = Config(signature_version="s3v4", s3={"addressing_style": "path"})
s3 = boto3.client(
    "s3",
    endpoint_url=os.getenv("S3_ENDPOINT") or None,
    region_name=os.getenv("S3_REGION", "us-east-1"),
    aws_access_key_id=os.getenv("S3_ACCESS_KEY") or None,
    aws_secret_access_key=os.getenv("S3_SECRET_KEY") or None,
    config=s3_config,
)

app = FastAPI(title="DataBridge Contributor Service", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGIN,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def start():
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8081")), reload=os.getenv("ENVIRONMENT", "development") != "production")


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class RegisterRequest(ApiModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    organization: Optional[str] = Field(default=None, max_length=160)
    country_code: Optional[str] = Field(default=None, min_length=2, max_length=2)


class LoginRequest(ApiModel):
    email: EmailStr
    password: str


class SubmissionCreate(ApiModel):
    project_id: Optional[str] = None
    project_name: str = Field(min_length=1, max_length=160)
    site: Optional[str] = Field(default=None, max_length=160)
    country_code: Optional[str] = Field(default=None, min_length=2, max_length=2)
    camera_id: Optional[str] = Field(default=None, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)


class FilePresignRequest(ApiModel):
    file_name: str = Field(min_length=1, max_length=255)
    content_type: str = "application/octet-stream"
    content_length: int = Field(default=0, ge=0, le=50 * 1024 * 1024 * 1024)


def require_role(user, *roles):
    if user.get("role") not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to perform this action")


def database_session():
    with Session(engine) as session:
        yield session


def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")


def safe_file_name(file_name: str) -> str:
    return "".join(character if character.isalnum() or character in ".-_" else "_" for character in file_name)


@app.get("/")
def root():
    return {
        "service": "DataBridge Contributor Service",
        "version": app.version,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health(db: Session = Depends(database_session)):
    db.execute(text("SELECT 1"))
    return {"status": "healthy", "service": "contributor"}


@app.post("/auth/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(database_session)):
    email = str(payload.email).lower()
    password_hash = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        user = db.execute(
            text("""INSERT INTO users (email, password_hash, role)
                    VALUES (:email, :password_hash, 'contributor')
                    RETURNING id, email, role"""),
            {"email": email, "password_hash": password_hash},
        ).mappings().one()
        db.execute(
            text("""INSERT INTO profiles (user_id, display_name, organization, country_code)
                    VALUES (:id, :display_name, :organization, :country_code)"""),
            {
                "id": user["id"],
                "display_name": payload.display_name.strip(),
                "organization": payload.organization,
                "country_code": payload.country_code.upper() if payload.country_code else None,
            },
        )
        db.commit()
        return {"user": dict(user)}
    except Exception as error:
        db.rollback()
        if getattr(error, "orig", None) and getattr(error.orig, "sqlstate", None) == "23505":
            raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
        raise


@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(database_session)):
    user = db.execute(
        text("""SELECT u.id, u.email, u.role, u.password_hash, p.display_name, p.organization, p.country_code
                FROM users u LEFT JOIN profiles p ON p.user_id = u.id
                WHERE u.email = :email AND u.status = 'active'"""),
        {"email": str(payload.email).lower()},
    ).mappings().one_or_none()
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    token_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    db.execute(
        text("""INSERT INTO auth_sessions (user_id, token_id, expires_at) VALUES (:id, :token_id, :expires_at)"""),
        {"id": user["id"], "token_id": token_id, "expires_at": expires_at},
    )
    db.commit()
    token = jwt.encode({"sub": str(user["id"]), "role": user["role"], "tokenId": token_id,
                        "exp": expires_at}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"token": token, "user": {
        "id": str(user["id"]), "email": user["email"], "role": user["role"],
        "displayName": user["display_name"], "organization": user["organization"],
        "countryCode": user["country_code"],
    }}


@app.get("/me")
def me(user=Depends(current_user), db: Session = Depends(database_session)):
    profile = db.execute(
        text("""SELECT u.id, u.email, u.role, p.display_name, p.organization, p.country_code, p.phone, p.avatar_url
                FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = :id"""),
        {"id": user["sub"]},
    ).mappings().one_or_none()
    if not profile:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return dict(profile)


@app.post("/submissions", status_code=201)
def create_submission(payload: SubmissionCreate, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    result = db.execute(
        text("""INSERT INTO submissions
                (contributor_id, project_id, project_name, site, country_code, camera_id, description)
                VALUES (:user_id, :project_id, :project_name, :site, :country_code, :camera_id, :description)
                RETURNING id, status, created_at"""),
        {
            "user_id": user["sub"], "project_id": payload.project_id, "project_name": payload.project_name,
            "site": payload.site, "country_code": payload.country_code.upper() if payload.country_code else None,
            "camera_id": payload.camera_id, "description": payload.description,
        },
    ).mappings().one()
    db.commit()
    return dict(result)


@app.get("/submissions")
def list_submissions(user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    rows = db.execute(
        text("""SELECT id, project_name, site, country_code, status, created_at
                FROM submissions WHERE contributor_id = :user_id ORDER BY created_at DESC"""),
        {"user_id": user["sub"]},
    ).mappings()
    return [dict(row) for row in rows]


@app.post("/storage/presigned-upload")
def presigned_upload(payload: FilePresignRequest, submission_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    submission = db.execute(
        text("SELECT id FROM submissions WHERE id = :id AND contributor_id = :user_id"),
        {"id": submission_id, "user_id": user["sub"]},
    ).one_or_none()
    if not submission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Submission not found")
    bucket = UPLOAD_BUCKET
    key = f"submissions/{submission_id}/{uuid.uuid4().hex}-{safe_file_name(payload.file_name)}"
    try:
        parameters = {"Bucket": bucket, "Key": key, "ContentType": payload.content_type}
        if payload.content_length:
            parameters["ContentLength"] = payload.content_length
        url = s3.generate_presigned_url("put_object", Params=parameters, ExpiresIn=900)
        file_id = db.execute(
            text("""INSERT INTO submission_files
                    (submission_id, uploaded_by, bucket, object_key, file_name, content_type, file_size)
                    VALUES (:submission_id, :uploaded_by, :bucket, :object_key, :file_name, :content_type, :file_size)
                    RETURNING id"""),
            {
                "submission_id": submission_id, "uploaded_by": user["sub"], "bucket": bucket,
                "object_key": key, "file_name": payload.file_name, "content_type": payload.content_type,
                "file_size": payload.content_length,
            },
        ).scalar_one()
        db.commit()
        return {"fileId": str(file_id), "bucket": bucket, "key": key, "uploadUrl": url, "expiresIn": 900}
    except (BotoCoreError, ClientError) as error:
        db.rollback()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error


@app.post("/storage/presigned-download")
def presigned_download(file_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    file = db.execute(
        text("""SELECT f.bucket, f.object_key FROM submission_files f
                JOIN submissions s ON s.id = f.submission_id
                WHERE f.id = :file_id AND s.contributor_id = :user_id"""),
        {"file_id": file_id, "user_id": user["sub"]},
    ).mappings().one_or_none()
    if not file:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    try:
        url = s3.generate_presigned_url(
            "get_object", Params={"Bucket": file["bucket"], "Key": file["object_key"]}, ExpiresIn=900
        )
        return {"downloadUrl": url, "expiresIn": 900}
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error
