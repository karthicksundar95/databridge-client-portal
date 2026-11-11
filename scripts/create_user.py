import argparse
import getpass
import os

import bcrypt
from sqlalchemy import create_engine, text


def main():
    parser = argparse.ArgumentParser(description="Provision an analyst or administrator account.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--role", choices=("analyst", "administrator"), required=True)
    args = parser.parse_args()

    password = getpass.getpass("Password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        parser.error("Password must contain at least 12 characters")
    if password != confirmation:
        parser.error("Passwords do not match")

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        parser.error("DATABASE_URL must be configured")

    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            user = connection.execute(
                text("""INSERT INTO users (email, password_hash, role)
                        VALUES (:email, :password_hash, CAST(:role AS user_role))
                        RETURNING id"""),
                {
                    "email": args.email.strip().lower(),
                    "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode(),
                    "role": args.role,
                },
            ).one()
            connection.execute(
                text("""INSERT INTO profiles (user_id, display_name)
                        VALUES (:user_id, :display_name)"""),
                {"user_id": user.id, "display_name": args.display_name.strip()},
            )
    finally:
        engine.dispose()
    print(f"Created {args.role} account for {args.email.strip().lower()}")


if __name__ == "__main__":
    main()
