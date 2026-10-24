import json
import logging
import os
from datetime import datetime, timedelta, timezone

log = logging.getLogger("state")

STATE_FILE = os.getenv("STATE_FILE", "cache/keys_state.json")
DATABASE_URL = os.getenv("DATABASE_URL", "")
OK_INTERVAL_SEC = int(os.getenv("OK_INTERVAL_SEC", "3600"))          # через сколько снова проверять рабочий
BACKOFF_BASE_SEC = int(os.getenv("BACKOFF_BASE_SEC", "3600"))        # первая задержка после неудачи
BACKOFF_FACTOR = float(os.getenv("BACKOFF_FACTOR", "2"))             # во сколько раз растёт задержка
BACKOFF_MAX_SEC = int(os.getenv("BACKOFF_MAX_SEC", str(7 * 86400)))  # потолок задержки
SKIP_RECHECK_SEC = int(os.getenv("SKIP_RECHECK_SEC", "86400"))       # для неподдерживаемых форматов
DELETE_AFTER_FAILS = int(os.getenv("DELETE_AFTER_FAILS", "1"))       # серия неудач для удаления
STATE_TTL_DAYS = float(os.getenv("STATE_TTL_DAYS", "30"))            # 0 = не чистить
SCHEMA_VERSION = 1


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def parse(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _defaults(label: str, now: datetime) -> dict:
    return {
        "label": label,
        "added_at": None,             # 1. когда добавлен (дата сообщения в форуме)
        "first_seen_at": iso(now),    # 1. когда скрипт впервые увидел
        "last_seen_at": iso(now),     # служебное: когда последний раз встретился в форуме
        "last_checked_at": None,      # 2. последняя проверка
        "last_success_at": None,      # 3. последняя успешная
        "last_fail_at": None,         # 4. последняя неуспешная
        "consecutive_ok": 0,          # 5. успешных подряд
        "total_ok": 0,                # 5.1 всего успешных
        "total_checks": 0,            # 6. всего проверок
        "consecutive_fail": 0,        # 7. неуспешных подряд
        "total_fail": 0,              # 7.1 всего неуспешных
        "last_error": None,           # 8. какая ошибка была
        "backoff_sec": 0,             # 10. текущая задержка backoff
        "next_check_at": iso(now),    # 9. когда проверять в следующий раз
    }


def describe(rec: dict) -> str:
    return (f"ok_streak={rec['consecutive_ok']} ok_total={rec['total_ok']} "
            f"fail_streak={rec['consecutive_fail']} fail_total={rec['total_fail']} "
            f"checks={rec['total_checks']} backoff={rec['backoff_sec']}s next={rec['next_check_at']}")


def describe_full(rec: dict) -> str:
    return (f"{describe(rec)} added={rec['added_at']} first_seen={rec['first_seen_at']} "
            f"last_checked={rec['last_checked_at']} last_ok={rec['last_success_at']} "
            f"last_fail={rec['last_fail_at']} last_error={rec['last_error']!r}")


class State:
    def __init__(self, path: str = STATE_FILE, dsn: str = DATABASE_URL):
        self.path = path
        self.dsn = dsn
        self.keys: dict = {}
        self.deleted: set = set()  # key_id, удалённые при очистке (для базы)

    # ---------- загрузка / сохранение ----------
    def load(self) -> None:
        if self.dsn:
            import state_db  # импорт здесь, чтобы без базы не требовать psycopg2
            log.info("хранилище состояния: база данных")
            # при ошибке чтения исключение останавливает запуск: с нуля не начинаем,
            # чтобы не затереть хорошее состояние пустым
            self.keys = state_db.load_all(self.dsn)
            return

        log.info("хранилище состояния: файл %s", self.path)
        log.debug("читаю состояние: %s", self.path)
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            log.info("файл состояния не найден, начинаю с нуля: %s", self.path)
            return
        except (OSError, ValueError) as e:
            log.warning("не удалось прочитать состояние (%s), начинаю с нуля", e)
            return
        self.keys = data.get("keys", {}) if isinstance(data, dict) else {}
        saved = data.get("saved_at") if isinstance(data, dict) else None
        log.info("состояние загружено: %d ключей, сохранено %s", len(self.keys), saved)

    def save(self) -> None:
        if self.dsn:
            import state_db
            state_db.save_all(self.dsn, self.keys, self.deleted)
            self.deleted.clear()
            return

        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": SCHEMA_VERSION, "saved_at": iso(utcnow()), "keys": self.keys},
                      f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, self.path)
        log.info("состояние сохранено: %d ключей, %d байт", len(self.keys), os.path.getsize(self.path))

    def prune(self, now: datetime) -> int:
        if STATE_TTL_DAYS <= 0:
            log.debug("очистка состояния отключена (STATE_TTL_DAYS=0)")
            return 0
        limit = now - timedelta(days=STATE_TTL_DAYS)
        old = []
        for kid, rec in self.keys.items():
            seen = parse(rec.get("last_seen_at")) or parse(rec.get("first_seen_at"))
            if seen is None or seen < limit:
                old.append(kid)
        for kid in old:
            log.debug("удаляю из состояния давно не встречавшийся ключ %s [%s]",
                      self.keys[kid].get("label"), kid[:8])
            del self.keys[kid]
            self.deleted.add(kid)
        log.info("очистка состояния: удалено %d записей старше %s дн.", len(old), STATE_TTL_DAYS)
        return len(old)

    # ---------- доступ ----------
    def get(self, kid: str) -> dict:
        return self.keys[kid]

    def touch(self, kid: str, label: str, added_at, now: datetime) -> dict:
        rec = self.keys.get(kid)
        if rec is None:
            rec = _defaults(label, now)
            self.keys[kid] = rec
            self.deleted.discard(kid)
            log.debug("новый ключ %s", label)
        else:
            for k, v in _defaults(label, now).items():  # дополняем записи старой схемы
                rec.setdefault(k, v)
            rec["label"] = label
            rec["last_seen_at"] = iso(now)
        if added_at is not None:
            current = parse(rec["added_at"])
            if current is None or added_at < current:
                rec["added_at"] = iso(added_at)
        return rec

    def is_due(self, rec: dict, now: datetime) -> bool:
        nxt = parse(rec.get("next_check_at"))
        return nxt is None or nxt <= now

    def is_dead(self, rec: dict) -> bool:
        return rec["consecutive_fail"] >= DELETE_AFTER_FAILS

    # ---------- запись результатов ----------
    def record_ok(self, kid: str, at: datetime, latency_ms) -> dict:
        rec = self.keys[kid]
        rec["last_checked_at"] = iso(at)
        rec["last_success_at"] = iso(at)
        rec["total_checks"] += 1
        rec["total_ok"] += 1
        rec["consecutive_ok"] += 1
        rec["consecutive_fail"] = 0
        rec["backoff_sec"] = 0
        rec["next_check_at"] = iso(at + timedelta(seconds=OK_INTERVAL_SEC))
        log.debug("%s: успех записан, серия успехов %d, backoff сброшен, следующая проверка %s",
                  rec["label"], rec["consecutive_ok"], rec["next_check_at"])
        return rec

    def record_fail(self, kid: str, at: datetime, error) -> dict:
        rec = self.keys[kid]
        prev = rec["backoff_sec"]
        new = BACKOFF_BASE_SEC if prev <= 0 else min(int(prev * BACKOFF_FACTOR), BACKOFF_MAX_SEC)
        rec["last_checked_at"] = iso(at)
        rec["last_fail_at"] = iso(at)
        rec["total_checks"] += 1
        rec["total_fail"] += 1
        rec["consecutive_fail"] += 1
        rec["consecutive_ok"] = 0
        rec["last_error"] = error
        rec["backoff_sec"] = new
        rec["next_check_at"] = iso(at + timedelta(seconds=new))
        log.debug("%s: неудача записана, серия неудач %d, backoff %ds -> %ds, следующая проверка %s",
                  rec["label"], rec["consecutive_fail"], prev, new, rec["next_check_at"])
        return rec

    def record_skip(self, kid: str, at: datetime, error) -> dict:
        """Формат не поддерживается: счётчики проверок не трогаем, ключ не считается мёртвым."""
        rec = self.keys[kid]
        rec["last_error"] = error
        rec["next_check_at"] = iso(at + timedelta(seconds=SKIP_RECHECK_SEC))
        log.debug("%s: пропуск записан (%s), следующая попытка %s",
                  rec["label"], error, rec["next_check_at"])
        return rec
