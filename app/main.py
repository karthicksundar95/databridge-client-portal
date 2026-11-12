import os
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from urllib.parse import quote

import bcrypt
import boto3
import jwt
import httpx
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://databridge:databridge_dev@localhost:5432/databridge")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEV_JWT_SECRET = "development-only-secret-change-me"
JWT_SECRET = os.getenv("JWT_SECRET", DEV_JWT_SECRET)
if ENVIRONMENT != "development" and (JWT_SECRET == DEV_JWT_SECRET or len(JWT_SECRET) < 32):
    raise RuntimeError("JWT_SECRET must be at least 32 characters outside development")
JWT_ALGORITHM = "HS256"
CORS_ORIGIN = [item.strip() for item in os.getenv("CORS_ORIGIN", "").split(",") if item]
UPLOAD_BUCKET = os.getenv("UPLOAD_BUCKET", "databridge-uploads")
DELIVERABLE_BUCKET = os.getenv("DELIVERABLE_BUCKET", "databridge-deliverables")
OTP_DELIVERY = os.getenv("OTP_DELIVERY", "resend")
OTP_TEST_CODE = os.getenv("OTP_TEST_CODE")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")

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

app = FastAPI(title="DataBridge Client Portal Service", version="0.1.0")
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
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    organization: Optional[str] = Field(default=None, max_length=160)
    country_code: Optional[str] = Field(default=None, min_length=2, max_length=2)


class LoginRequest(ApiModel):
    email: EmailStr
    password: str


class PasswordChangeRequest(ApiModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


class SignupVerifyRequest(ApiModel):
    challenge_id: uuid.UUID
    code: str = Field(pattern=r"^\d{6}$")


class SignupResendRequest(ApiModel):
    challenge_id: uuid.UUID


class AdminUserStatusRequest(ApiModel):
    status: Literal["active", "suspended"]


class AdminUserCreateRequest(ApiModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    role: Literal["contributor", "analyst", "administrator"]
    organization: Optional[str] = Field(default=None, max_length=160)


class AdminUserUpdateRequest(ApiModel):
    role: Literal["contributor", "analyst", "administrator"]


class AdminDeleteUserRequest(ApiModel):
    confirmation: Literal["DELETE"]
    reason: str = Field(min_length=1, max_length=500)


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
    content_length: int = Field(default=0, ge=0, le=5 * 1024 * 1024 * 1024)


class FileCompleteRequest(ApiModel):
    file_id: uuid.UUID
    key: str = Field(min_length=1, max_length=1024)
    file_name: str = Field(min_length=1, max_length=255)
    content_type: str = Field(min_length=1, max_length=255)
    content_length: int = Field(ge=0, le=5 * 1024 * 1024 * 1024)


def require_role(user, *roles):
    if user.get("role") not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to perform this action")


def write_audit_log(db: Session, actor_id: str, action: str, target_type: str, target_id: str, details: str):
    db.execute(
        text("""INSERT INTO audit_logs (actor_id, action, target_type, target_id, details)
                VALUES (:actor_id, :action, :target_type, :target_id, :details)"""),
        {
            "actor_id": actor_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
        },
    )


def generate_temporary_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_"
    password = list(secrets.choice(alphabet) for _ in range(20))
    password[0] = secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
    password[1] = secrets.choice("abcdefghijkmnopqrstuvwxyz")
    password[2] = secrets.choice("23456789")
    password[3] = secrets.choice("!@#$%^&*-_")
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def database_session():
    with Session(engine) as session:
        yield session


def current_user(authorization: Optional[str] = Header(default=None), db: Session = Depends(database_session)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if not payload.get("sub") or not payload.get("tokenId"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    session = db.execute(
        text("""SELECT u.role::text AS role FROM auth_sessions s JOIN users u ON u.id = s.user_id
                WHERE s.user_id = :user_id AND s.token_id = :token_id
                  AND s.revoked_at IS NULL AND s.expires_at > NOW() AND u.status = 'active'"""),
        {"user_id": payload["sub"], "token_id": payload["tokenId"]},
    ).mappings().one_or_none()
    if not session or session["role"] != payload.get("role"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return payload


def safe_file_name(file_name: str) -> str:
    return "".join(character if character.isalnum() or character in ".-_" else "_" for character in file_name)


def otp_digest(code: str) -> str:
    return hmac.new(JWT_SECRET.encode(), code.encode(), hashlib.sha256).hexdigest()


def signup_email_html(code: str) -> str:
    return f"""<!doctype html>
<html><body style="margin:0;background:#eef2fa;color:#172554;font-family:Arial,sans-serif">
<div style="padding:40px 18px"><div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e3e9f4;border-radius:16px;overflow:hidden">
<div style="padding:28px 32px;border-bottom:1px solid #edf0f5">
<div style="font-size:21px;font-weight:700;color:#172554;display:flex;align-items:center">
<svg width="29" height="29" viewBox="0 0 29 29" fill="none" style="margin-right:10px">
<rect x="3" y="7" width="7" height="18" rx="4" transform="rotate(-32 3 7)" fill="#3155b8" fill-opacity=".55"/>
<rect x="11" y="2" width="7" height="24" rx="4" transform="rotate(-32 11 2)" fill="#3155b8"/>
<rect x="19" y="1" width="7" height="18" rx="4" transform="rotate(-32 19 1)" fill="#3155b8" fill-opacity=".75"/>
</svg>DataBridge</div></div>
<div style="padding:34px 32px 38px"><div style="font-size:11px;font-weight:700;letter-spacing:1.4px;color:#3155b8;text-transform:uppercase">Signup verification</div>
<h1 style="margin:10px 0 12px;font-size:28px;color:#172554">Confirm your email</h1>
<p style="margin:0;color:#64748b;font-size:15px;line-height:1.65">Use this code to finish creating your DataBridge client account.</p>
<div style="margin:28px 0;padding:20px;text-align:center;border:1px solid #dce5f7;border-radius:12px;background:#f7f9fe">
<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;color:#64748b;text-transform:uppercase">Your verification code</div>
<div style="margin-top:9px;font-size:35px;font-weight:700;letter-spacing:9px;color:#3155b8;user-select:all">{code}</div>
<div style="margin-top:12px;color:#64748b;font-size:11px">Enter this code in the DataBridge signup window.</div></div>
<p style="margin:0;color:#64748b;font-size:13px;line-height:1.6">This code expires in <strong style="color:#334155">10 minutes</strong>. If you did not request this, you can safely ignore this email.</p>
</div><div style="padding:18px 32px;background:#fafbfe;border-top:1px solid #edf0f5;color:#94a3b8;font-size:11px">DataBridge · Securely share project data and follow it through review.</div>
</div></div></body></html>"""


def send_signup_otp(email: str, code: str):
    if OTP_DELIVERY == "mock":
        print(f"Mock signup OTP for {email}: {code}")
        return
    if not RESEND_API_KEY:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Email verification is not configured")
    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": RESEND_FROM_EMAIL, "to": [email], "subject": "Your DataBridge signup verification code", "html": signup_email_html(code)},
            timeout=10,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        if error.response.status_code == status.HTTP_403_FORBIDDEN:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "Email delivery is restricted until a sending domain is verified in Resend.",
            ) from error
        if error.response.status_code in {status.HTTP_401_UNAUTHORIZED, status.HTTP_422_UNPROCESSABLE_ENTITY}:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "Email delivery is not configured correctly. Check the Resend API key and sender address.",
            ) from error
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Verification email could not be sent") from error
    except httpx.HTTPError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Verification email could not be sent") from error


@app.get("/")
def root():
    return {
        "service": "DataBridge Client Portal Service",
        "version": app.version,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health(db: Session = Depends(database_session)):
    db.execute(text("SELECT 1"))
    return {"status": "healthy", "service": "client-portal"}


@app.post("/auth/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(database_session)):
    email = str(payload.email).lower()
    existing = db.execute(text("SELECT status FROM users WHERE email = :email"), {"email": email}).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    pending = db.execute(
        text("SELECT id, last_sent_at FROM signup_challenges WHERE email = :email"),
        {"email": email},
    ).mappings().one_or_none()
    if pending and pending["last_sent_at"] > datetime.now(timezone.utc) - timedelta(seconds=60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Please wait before requesting another code")
    password_hash = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt(rounds=12)).decode()
    code = OTP_TEST_CODE if OTP_DELIVERY == "mock" and OTP_TEST_CODE else f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = pending["id"] if pending else uuid.uuid4()
    try:
        db.execute(
            text("""INSERT INTO signup_challenges
                    (id, email, password_hash, display_name, organization, country_code, otp_hash, expires_at)
                    VALUES (:id, :email, :password_hash, :display_name, :organization, :country_code, :otp_hash, :expires_at)
                    ON CONFLICT (email) DO UPDATE SET
                      id = EXCLUDED.id, password_hash = EXCLUDED.password_hash, display_name = EXCLUDED.display_name,
                      organization = EXCLUDED.organization, country_code = EXCLUDED.country_code,
                      otp_hash = EXCLUDED.otp_hash, attempts = 0, last_sent_at = NOW(), expires_at = EXCLUDED.expires_at"""),
            {
                "id": challenge_id, "email": email, "password_hash": password_hash,
                "display_name": payload.display_name.strip(),
                "organization": payload.organization,
                "country_code": payload.country_code.upper() if payload.country_code else None,
                "otp_hash": otp_digest(code),
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
            },
        )
        db.commit()
        send_signup_otp(email, code)
        return {"challengeId": str(challenge_id), "email": email, "expiresIn": 600}
    except (IntegrityError, HTTPException):
        db.rollback()
        raise


@app.post("/auth/register/verify", status_code=201)
def verify_signup(payload: SignupVerifyRequest, db: Session = Depends(database_session)):
    challenge = db.execute(
        text("SELECT * FROM signup_challenges WHERE id = :id"),
        {"id": payload.challenge_id},
    ).mappings().one_or_none()
    if not challenge:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Signup verification has expired or is invalid")
    if challenge["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_410_GONE, "This verification code has expired")
    if challenge["attempts"] >= 5:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many verification attempts")
    if not hmac.compare_digest(challenge["otp_hash"], otp_digest(payload.code)):
        db.execute(text("UPDATE signup_challenges SET attempts = attempts + 1 WHERE id = :id"), {"id": payload.challenge_id})
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The verification code is incorrect")
    try:
        user = db.execute(
            text("""INSERT INTO users (email, password_hash, role)
                    VALUES (:email, :password_hash, 'contributor')
                    RETURNING id, email, role"""),
            {"email": challenge["email"], "password_hash": challenge["password_hash"]},
        ).mappings().one()
        db.execute(
            text("""INSERT INTO profiles (user_id, display_name, organization, country_code)
                    VALUES (:id, :display_name, :organization, :country_code)"""),
            {"id": user["id"], "display_name": challenge["display_name"], "organization": challenge["organization"], "country_code": challenge["country_code"]},
        )
        db.execute(text("DELETE FROM signup_challenges WHERE id = :id"), {"id": payload.challenge_id})
        db.commit()
        return {"user": dict(user)}
    except IntegrityError as error:
        db.rollback()
        if getattr(error, "orig", None) and getattr(error.orig, "sqlstate", None) == "23505":
            raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
        raise


@app.post("/auth/register/resend")
def resend_signup(payload: SignupResendRequest, db: Session = Depends(database_session)):
    challenge = db.execute(text("SELECT * FROM signup_challenges WHERE id = :id"), {"id": payload.challenge_id}).mappings().one_or_none()
    if not challenge:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Signup verification has expired or is invalid")
    if challenge["last_sent_at"] > datetime.now(timezone.utc) - timedelta(seconds=60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Please wait before requesting another code")
    code = OTP_TEST_CODE if OTP_DELIVERY == "mock" and OTP_TEST_CODE else f"{secrets.randbelow(1_000_000):06d}"
    db.execute(
        text("UPDATE signup_challenges SET otp_hash = :otp_hash, attempts = 0, last_sent_at = NOW(), expires_at = :expires_at WHERE id = :id"),
        {"id": payload.challenge_id, "otp_hash": otp_digest(code), "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)},
    )
    db.commit()
    send_signup_otp(challenge["email"], code)
    return {"expiresIn": 600}


@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(database_session)):
    user = db.execute(
        text("""SELECT u.id, u.email, u.role, u.password_hash, u.must_change_password,
                       p.display_name, p.organization, p.country_code
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
        "mustChangePassword": user["must_change_password"],
    }}


@app.post("/auth/logout", status_code=204)
def logout(user=Depends(current_user), db: Session = Depends(database_session)):
    db.execute(
        text("UPDATE auth_sessions SET revoked_at = NOW() WHERE token_id = :token_id AND revoked_at IS NULL"),
        {"token_id": user["tokenId"]},
    )
    db.commit()


@app.post("/auth/password")
def change_password(payload: PasswordChangeRequest, user=Depends(current_user), db: Session = Depends(database_session)):
    account = db.execute(
        text("SELECT password_hash FROM users WHERE id = :id AND status = 'active'"),
        {"id": user["sub"]},
    ).scalar_one_or_none()
    if not account or not bcrypt.checkpw(payload.current_password.encode(), account.encode()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The current password is incorrect")
    if payload.current_password == payload.new_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The new password must be different")
    db.execute(
        text("UPDATE users SET password_hash = :password_hash, must_change_password = FALSE WHERE id = :id"),
        {"password_hash": bcrypt.hashpw(payload.new_password.encode(), bcrypt.gensalt(rounds=12)).decode(), "id": user["sub"]},
    )
    db.execute(
        text("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = :id AND token_id <> :token_id AND revoked_at IS NULL"),
        {"id": user["sub"], "token_id": user["tokenId"]},
    )
    write_audit_log(db, user["sub"], "user.password_changed", "user", user["sub"], "Password changed by account owner")
    db.commit()
    return {"status": "password_changed"}


@app.get("/me")
def me(user=Depends(current_user), db: Session = Depends(database_session)):
    profile = db.execute(
        text("""SELECT u.id, u.email, u.role, u.must_change_password,
                       p.display_name, p.organization, p.country_code, p.phone, p.avatar_url
                FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = :id"""),
        {"id": user["sub"]},
    ).mappings().one_or_none()
    if not profile:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return {
        "id": str(profile["id"]),
        "email": profile["email"],
        "role": profile["role"],
        "mustChangePassword": profile["must_change_password"],
        "displayName": profile["display_name"],
        "organization": profile["organization"],
        "countryCode": profile["country_code"].strip() if profile["country_code"] else None,
        "phone": profile["phone"],
        "avatarUrl": profile["avatar_url"],
    }


@app.post("/admin/users", status_code=201)
def admin_create_user(payload: AdminUserCreateRequest, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "administrator")
    email = str(payload.email).lower()
    existing = db.execute(text("SELECT id FROM users WHERE email = :email"), {"email": email}).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    temporary_password = generate_temporary_password()
    try:
        created = db.execute(
            text("""INSERT INTO users (email, password_hash, role, must_change_password)
                    VALUES (:email, :password_hash, CAST(:role AS user_role), TRUE)
                    RETURNING id, email, role::text AS role, status, created_at"""),
            {
                "email": email,
                "password_hash": bcrypt.hashpw(temporary_password.encode(), bcrypt.gensalt(rounds=12)).decode(),
                "role": payload.role,
            },
        ).mappings().one()
        db.execute(
            text("""INSERT INTO profiles (user_id, display_name, organization)
                    VALUES (:id, :display_name, :organization)"""),
            {"id": created["id"], "display_name": payload.display_name.strip(), "organization": payload.organization},
        )
        write_audit_log(db, user["sub"], "user.created", "user", str(created["id"]), f"Created {payload.role} account")
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists") from error
    return {
        "id": str(created["id"]),
        "email": created["email"],
        "role": created["role"],
        "status": created["status"],
        "temporaryPassword": temporary_password,
        "mustChangePassword": True,
    }


@app.get("/admin/users")
def admin_users(user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "administrator")
    rows = db.execute(
        text("""SELECT u.id, u.email, u.role::text AS role, u.status, u.must_change_password,
                       u.created_at, u.updated_at,
                       p.display_name, p.organization
                FROM users u LEFT JOIN profiles p ON p.user_id = u.id
                ORDER BY u.created_at DESC""")
    ).mappings()
    return [{
        "id": str(row["id"]),
        "email": row["email"],
        "role": row["role"],
        "status": row["status"],
        "mustChangePassword": row["must_change_password"],
        "displayName": row["display_name"],
        "organization": row["organization"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    } for row in rows]


@app.patch("/admin/users/{user_id}")
def admin_update_user(
    user_id: uuid.UUID,
    payload: AdminUserUpdateRequest,
    user=Depends(current_user),
    db: Session = Depends(database_session),
):
    require_role(user, "administrator")
    target = db.execute(
        text("SELECT id, role::text AS role, status FROM users WHERE id = :id"),
        {"id": user_id},
    ).mappings().one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if str(target["id"]) == user["sub"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own role")
    if target["role"] == "administrator" and payload.role != "administrator":
        active_admins = db.execute(
            text("SELECT COUNT(*) FROM users WHERE role = 'administrator' AND status = 'active'"),
        ).scalar_one()
        if active_admins <= 1 and target["status"] == "active":
            raise HTTPException(status.HTTP_409_CONFLICT, "The last active administrator cannot be demoted")
    db.execute(
        text("UPDATE users SET role = CAST(:role AS user_role) WHERE id = :id"),
        {"role": payload.role, "id": user_id},
    )
    write_audit_log(db, user["sub"], "user.role_changed", "user", str(user_id), f"Role changed from {target['role']} to {payload.role}")
    db.commit()
    return {"id": str(user_id), "role": payload.role}


@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_user_password(user_id: uuid.UUID, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "administrator")
    target = db.execute(
        text("SELECT id, email, status FROM users WHERE id = :id"),
        {"id": user_id},
    ).mappings().one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target["status"] == "deleted":
        raise HTTPException(status.HTTP_409_CONFLICT, "Deleted accounts cannot be reset")
    temporary_password = generate_temporary_password()
    db.execute(
        text("""UPDATE users SET password_hash = :password_hash, must_change_password = TRUE
                WHERE id = :id"""),
        {"password_hash": bcrypt.hashpw(temporary_password.encode(), bcrypt.gensalt(rounds=12)).decode(), "id": user_id},
    )
    db.execute(
        text("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = :id AND revoked_at IS NULL"),
        {"id": user_id},
    )
    write_audit_log(db, user["sub"], "user.password_reset", "user", str(user_id), "Temporary password issued by administrator")
    db.commit()
    return {"id": str(user_id), "email": target["email"], "temporaryPassword": temporary_password, "mustChangePassword": True}


@app.patch("/admin/users/{user_id}/status")
def admin_update_user_status(
    user_id: uuid.UUID,
    payload: AdminUserStatusRequest,
    user=Depends(current_user),
    db: Session = Depends(database_session),
):
    require_role(user, "administrator")
    target = db.execute(
        text("SELECT id, email, role::text AS role, status FROM users WHERE id = :id"),
        {"id": user_id},
    ).mappings().one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if str(target["id"]) == user["sub"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own account status")
    if target["status"] == "deleted":
        raise HTTPException(status.HTTP_409_CONFLICT, "Deleted accounts cannot be reactivated")
    if target["role"] == "administrator" and payload.status == "suspended":
        active_admins = db.execute(
            text("SELECT COUNT(*) FROM users WHERE role = 'administrator' AND status = 'active'"),
        ).scalar_one()
        if active_admins <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "The last active administrator cannot be suspended")
    db.execute(
        text("UPDATE users SET status = :status WHERE id = :id"),
        {"status": payload.status, "id": user_id},
    )
    if payload.status == "suspended":
        db.execute(
            text("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = :id AND revoked_at IS NULL"),
            {"id": user_id},
        )
    write_audit_log(db, user["sub"], f"user.{payload.status}", "user", str(user_id), f"Account status changed from {target['status']}")
    db.commit()
    return {"id": str(user_id), "status": payload.status}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: uuid.UUID,
    payload: AdminDeleteUserRequest,
    user=Depends(current_user),
    db: Session = Depends(database_session),
):
    require_role(user, "administrator")
    target = db.execute(
        text("SELECT id, email, role::text AS role, status FROM users WHERE id = :id FOR UPDATE"),
        {"id": user_id},
    ).mappings().one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if str(target["id"]) == user["sub"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    if target["status"] == "deleted":
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already deleted")
    if target["role"] == "administrator":
        active_admins = db.execute(
            text("SELECT COUNT(*) FROM users WHERE role = 'administrator' AND status = 'active'"),
        ).scalar_one()
        if active_admins <= 1 and target["status"] == "active":
            raise HTTPException(status.HTTP_409_CONFLICT, "The last active administrator cannot be deleted")
    anonymized_email = f"deleted+{target['id']}@invalid.local"
    db.execute(
        text("""UPDATE users
                SET email = :email, password_hash = :password_hash, status = 'deleted'
                WHERE id = :id"""),
        {
            "email": anonymized_email,
            "password_hash": bcrypt.hashpw(secrets.token_urlsafe(32).encode(), bcrypt.gensalt(rounds=12)).decode(),
            "id": user_id,
        },
    )
    db.execute(
        text("""UPDATE profiles
                SET display_name = 'Deleted user', organization = NULL, country_code = NULL,
                    phone = NULL, avatar_url = NULL
                WHERE user_id = :id"""),
        {"id": user_id},
    )
    db.execute(
        text("UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = :id AND revoked_at IS NULL"),
        {"id": user_id},
    )
    write_audit_log(db, user["sub"], "user.deleted", "user", str(user_id), payload.reason.strip())
    db.commit()
    return {"id": str(user_id), "status": "deleted"}


@app.get("/admin/audit")
def admin_audit(user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "administrator")
    rows = db.execute(
        text("""SELECT a.id, a.action, a.target_type, a.target_id, a.details, a.created_at,
                       u.email AS actor_email
                FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
                ORDER BY a.created_at DESC LIMIT 200""")
    ).mappings()
    return [{
        "id": str(row["id"]),
        "action": row["action"],
        "targetType": row["target_type"],
        "targetId": str(row["target_id"]) if row["target_id"] else None,
        "details": row["details"],
        "createdAt": row["created_at"],
        "actorEmail": row["actor_email"],
    } for row in rows]


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
        text("""SELECT s.id, s.project_name, s.site, s.country_code, s.status, s.created_at,
                       COUNT(f.id) AS file_count
                FROM submissions s LEFT JOIN submission_files f ON f.submission_id = s.id
                WHERE s.contributor_id = :user_id
                GROUP BY s.id ORDER BY s.created_at DESC"""),
        {"user_id": user["sub"]},
    ).mappings()
    return [{
        "id": str(row["id"]),
        "projectName": row["project_name"],
        "site": row["site"],
        "countryCode": row["country_code"].strip() if row["country_code"] else None,
        "status": row["status"],
        "createdAt": row["created_at"],
        "fileCount": row["file_count"],
    } for row in rows]


@app.get("/submissions/{submission_id}/files")
def list_submission_files(submission_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    if user.get("role") not in {"contributor", "analyst", "administrator"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to view submission files")
    submission = db.execute(
        text("""SELECT id, contributor_id FROM submissions
                WHERE id = :submission_id
                  AND (contributor_id = :user_id OR :role IN ('analyst', 'administrator'))"""),
        {"submission_id": submission_id, "user_id": user["sub"], "role": user["role"]},
    ).mappings().one_or_none()
    if not submission:
        return []

    prefix = f"submissions/{submission_id}/"
    registered_keys = set(db.execute(
        text("SELECT object_key FROM submission_files WHERE submission_id = :submission_id"),
        {"submission_id": submission_id},
    ).scalars())
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=UPLOAD_BUCKET, Prefix=prefix):
            for stored_object in page.get("Contents", []):
                object_key = stored_object["Key"]
                if object_key in registered_keys:
                    continue
                legacy_name = object_key.removeprefix(prefix)
                file_id, separator, file_name = legacy_name.partition("-")
                if not separator or len(file_id) != 32 or not file_id.isalnum() or not file_name:
                    continue
                try:
                    uuid.UUID(hex=file_id)
                except ValueError:
                    continue
                metadata = s3.head_object(Bucket=UPLOAD_BUCKET, Key=object_key)
                db.execute(
                    text("""INSERT INTO submission_files
                            (submission_id, uploaded_by, bucket, object_key, file_name, content_type, file_size)
                            VALUES (:submission_id, :uploaded_by, :bucket, :object_key, :file_name, :content_type, :file_size)
                            ON CONFLICT (object_key) DO NOTHING"""),
                    {
                        "submission_id": submission_id,
                        "uploaded_by": submission["contributor_id"],
                        "bucket": UPLOAD_BUCKET,
                        "object_key": object_key,
                        "file_name": file_name,
                        "content_type": metadata.get("ContentType") or "application/octet-stream",
                        "file_size": metadata["ContentLength"],
                    },
                )
                registered_keys.add(object_key)
        db.commit()
    except (BotoCoreError, ClientError) as error:
        db.rollback()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Uploaded files could not be retrieved from object storage") from error

    rows = db.execute(
        text("""SELECT id, file_name, content_type, file_size, created_at
                FROM submission_files
                WHERE submission_id = :submission_id
                ORDER BY created_at"""),
        {"submission_id": submission_id},
    ).mappings()
    return [{
        "id": str(row["id"]),
        "fileName": row["file_name"],
        "contentType": row["content_type"],
        "fileSize": row["file_size"],
        "createdAt": row["created_at"],
    } for row in rows]


@app.delete("/submissions/{submission_id}", status_code=204)
def delete_submission(submission_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    submission = db.execute(
        text("""SELECT id FROM submissions
                WHERE id = :submission_id AND contributor_id = :user_id"""),
        {"submission_id": submission_id, "user_id": user["sub"]},
    ).one_or_none()
    if not submission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Submission not found")

    prefix = f"submissions/{submission_id}/"
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=UPLOAD_BUCKET, Prefix=prefix):
            for stored_object in page.get("Contents", []):
                s3.delete_object(Bucket=UPLOAD_BUCKET, Key=stored_object["Key"])
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Incomplete upload could not be cleaned up") from error

    db.execute(
        text("DELETE FROM submissions WHERE id = :submission_id AND contributor_id = :user_id"),
        {"submission_id": submission_id, "user_id": user["sub"]},
    )
    db.commit()
    return None


@app.get("/reports")
def list_reports(user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    rows = db.execute(
        text("""SELECT d.id, d.file_name, d.published_at, s.id AS submission_id, s.project_name
                FROM deliverables d JOIN submissions s ON s.id = d.submission_id
                WHERE s.contributor_id = :user_id ORDER BY d.published_at DESC"""),
        {"user_id": user["sub"]},
    ).mappings()
    return [{
        "id": str(row["id"]),
        "fileName": row["file_name"],
        "publishedAt": row["published_at"],
        "submissionId": str(row["submission_id"]),
        "projectName": row["project_name"],
    } for row in rows]


@app.post("/storage/presigned-report-download")
def presigned_report_download(report_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    report = db.execute(
        text("""SELECT d.bucket, d.object_key FROM deliverables d
                JOIN submissions s ON s.id = d.submission_id
                WHERE d.id = :report_id AND s.contributor_id = :user_id"""),
        {"report_id": report_id, "user_id": user["sub"]},
    ).mappings().one_or_none()
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    try:
        url = s3.generate_presigned_url(
            "get_object", Params={"Bucket": report["bucket"], "Key": report["object_key"]}, ExpiresIn=900
        )
        return {"downloadUrl": url, "expiresIn": 900}
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error


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
    file_id = uuid.uuid4()
    key = f"submissions/{submission_id}/{file_id.hex}-{safe_file_name(payload.file_name)}"
    try:
        parameters = {"Bucket": bucket, "Key": key, "ContentType": payload.content_type}
        if payload.content_length:
            parameters["ContentLength"] = payload.content_length
        url = s3.generate_presigned_url("put_object", Params=parameters, ExpiresIn=900)
        return {"fileId": str(file_id), "bucket": bucket, "key": key, "uploadUrl": url, "expiresIn": 900}
    except (BotoCoreError, ClientError) as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error


@app.post("/storage/complete-upload")
def complete_upload(payload: FileCompleteRequest, submission_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    require_role(user, "contributor")
    submission = db.execute(
        text("SELECT id FROM submissions WHERE id = :id AND contributor_id = :user_id"),
        {"id": submission_id, "user_id": user["sub"]},
    ).one_or_none()
    if not submission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Submission not found")
    expected_prefix = f"submissions/{submission_id}/{payload.file_id.hex}-"
    if not payload.key.startswith(expected_prefix):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload key does not match the authorized file")
    try:
        stored_object = s3.head_object(Bucket=UPLOAD_BUCKET, Key=payload.key)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload the file before completing it") from error
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Uploaded object could not be verified") from error
    except BotoCoreError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error
    if stored_object["ContentLength"] != payload.content_length:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file size does not match")
    if stored_object.get("ContentType") != payload.content_type:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file type does not match")

    file_id = db.execute(
        text("""INSERT INTO submission_files
                (submission_id, uploaded_by, bucket, object_key, file_name, content_type, file_size)
                VALUES (:submission_id, :uploaded_by, :bucket, :object_key, :file_name, :content_type, :file_size)
                ON CONFLICT (object_key) DO UPDATE SET file_name = EXCLUDED.file_name
                WHERE submission_files.submission_id = EXCLUDED.submission_id
                  AND submission_files.uploaded_by = EXCLUDED.uploaded_by
                RETURNING id"""),
        {
            "submission_id": submission_id, "uploaded_by": user["sub"], "bucket": UPLOAD_BUCKET,
            "object_key": payload.key, "file_name": payload.file_name,
            "content_type": payload.content_type, "file_size": payload.content_length,
        },
    ).scalar_one_or_none()
    if not file_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "File is already registered to another submission")
    db.commit()
    return {"fileId": str(file_id)}


@app.post("/storage/presigned-download")
def presigned_download(file_id: str, user=Depends(current_user), db: Session = Depends(database_session)):
    if user.get("role") not in {"contributor", "analyst", "administrator"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to download submission files")
    file = db.execute(
        text("""SELECT f.bucket, f.object_key, f.file_name FROM submission_files f
                JOIN submissions s ON s.id = f.submission_id
                WHERE f.id = :file_id
                  AND (s.contributor_id = :user_id OR :role IN ('analyst', 'administrator'))"""),
        {"file_id": file_id, "user_id": user["sub"], "role": user["role"]},
    ).mappings().one_or_none()
    if not file:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    try:
        s3.head_object(Bucket=file["bucket"], Key=file["object_key"])
        url = s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": file["bucket"],
                "Key": file["object_key"],
                "ResponseContentDisposition": f"attachment; filename*=UTF-8''{quote(file['file_name'])}",
            },
            ExpiresIn=900,
        )
        return {"downloadUrl": url, "expiresIn": 900}
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "This file is no longer available in object storage. Please re-upload it.",
            ) from error
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error
    except BotoCoreError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Object storage is unavailable") from error
