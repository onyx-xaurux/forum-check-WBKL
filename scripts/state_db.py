import logging
import time

import psycopg2
from psycopg2.extras import Json, execute_values

log = logging.getLogger("db")

DDL = """
CREATE TABLE IF NOT EXISTS key_state (
    key_id     TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def connect(dsn: str):
    last = None
    for attempt in range(1, 4):  # база может просыпаться после простоя
        try:
            conn = psycopg2.connect(dsn, connect_timeout=20)
            log.debug("подключение к базе установлено (попытка %d)", attempt)
            return conn
        except psycopg2.OperationalError as e:
            last = e
            log.warning("не удалось подключиться к базе (попытка %d/3): %s",
                        attempt, str(e).strip()[:200])
            time.sleep(3 * attempt)
    raise last


def load_all(dsn: str) -> dict:
    log.debug("читаю состояние из базы")
    conn = connect(dsn)
    try:
        with conn, conn.cursor() as cur:
            cur.execute(DDL)
            cur.execute("SELECT key_id, data FROM key_state")
            rows = cur.fetchall()
        log.info("из базы прочитано записей: %d", len(rows))
        return {kid: data for kid, data in rows}
    finally:
        conn.close()


def save_all(dsn: str, keys: dict, deleted: set) -> None:
    log.debug("записываю состояние в базу: %d ключей, к удалению %d", len(keys), len(deleted))
    conn = connect(dsn)
    try:
        with conn, conn.cursor() as cur:
            cur.execute(DDL)
            if keys:
                execute_values(
                    cur,
                    "INSERT INTO key_state (key_id, data, updated_at) VALUES %s "
                    "ON CONFLICT (key_id) DO UPDATE "
                    "SET data = EXCLUDED.data, updated_at = now()",
                    [(kid, Json(rec)) for kid, rec in keys.items()],
                    template="(%s, %s, now())",
                    page_size=500,
                )
            if deleted:
                cur.execute("DELETE FROM key_state WHERE key_id = ANY(%s)", (list(deleted),))
        log.info("в базу записано ключей: %d, удалено записей: %d", len(keys), len(deleted))
    finally:
        conn.close()
