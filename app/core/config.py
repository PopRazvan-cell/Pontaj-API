import os
from urllib.parse import quote_plus
from dotenv import load_dotenv

load_dotenv()

class Settings:
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")
    MYSQL_DB = os.getenv("MYSQL_DB", "")

    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        pw = quote_plus(MYSQL_PASSWORD)
        DATABASE_URL = f"mysql+asyncmy://{MYSQL_USER}:{pw}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
    DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
    DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "3"))
    DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))
    SQL_ECHO = os.getenv("SQL_ECHO", "0") == "1"

    # tokens per client
    API_TOKEN_FRONTEND = os.getenv("API_TOKEN_FRONTEND", "")
    API_TOKEN_ADMIN = os.getenv("API_TOKEN_ADMIN", "")
    API_TOKEN_MOBILE = os.getenv("API_TOKEN_MOBILE", "")

settings = Settings()