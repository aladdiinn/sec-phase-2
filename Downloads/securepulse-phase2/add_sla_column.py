import os
from sqlalchemy import create_engine, text

DATABASE_URL = "postgresql+psycopg://securepulse:securepulse_pass@127.0.0.1:5432/securepulse_db"

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE cases ADD COLUMN sla_breached BOOLEAN DEFAULT FALSE;"))
        conn.commit()
        print("✅ Column added successfully!")
    except Exception as e:
        print(f"❌ Error: {e}")
        conn.rollback()