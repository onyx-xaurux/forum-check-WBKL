import asyncio
import logging
import os
import queue
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from telethon import TelegramClient
from telethon.errors import (ChatAdminRequiredError, FloodWaitError,
                             MessageDeleteForbiddenError)
from telethon.sessions import StringSession

import check_keys as ck
import key_state as ks

ck.setup_logging()
log = logging.getLogger("forum")

_PRE = r"(?<![A-Za-z0-9+.\-])"  # чтобы не цеплять ss:// внутри wss://
KEY_RE = re.compile(_PRE + "(?:" + "|".join(re.escape(s) for s in ck.SCHEMES) + r")[^\s<>\"'`]+")
UNSUP_RE = re.compile(_PRE + "(?:" + "|".join(re.escape(s) for s in ck.UNSUPPORTED_SCHEMES) + ")")


def need(name: str) -> str:
    value = os.getenv(name)
    if not value:
        log.warning("Не задана переменная окружения %s", name)
        sys.exit(1)
    return value


def parse_chat(value: str):
    """Понимает username, числовой id и ссылки t.me. Возвращает (чат, id_топика)."""
    v = value.strip()
    v = re.sub(r"^https?://", "", v)
    v = re.sub(r"^(?:www\.)?t(?:elegram)?\.me/", "", v)
    v = v.lstrip("@").split("?")[0].strip("/")
    parts = v.split("/")
    if parts[0] == "c" and len(parts) >= 2 and parts[1].isdigit():  # приватная группа
        topic = int(parts[2]) if len(parts) >= 4 and parts[2].isdigit() else 0
        return int("-100" + parts[1]), topic
    if parts[0].lstrip("-").isdigit():
        return int(parts[0]), 0
    # t.me/группа/топик/сообщение: топик берём только из полной ссылки на сообщение
    topic = int(parts[1]) if len(parts) >= 3 and parts[1].isdigit() else 0
    return parts[0], topic


def extract(msg):
    text = msg.raw_text or ""
    for e in msg.entities or []:  # ссылки, спрятанные в сущностях сообщения
        url = getattr(e, "url", None)
        if url:
            text += "\n" + url
    keys = [k.rstrip(".,;)") for k in KEY_RE.findall(text)]
    return keys, bool(UNSUP_RE.search(text))


def run_checks(items) -> dict:
    """items: [(key_id, key)] -> {key_id: CheckResult}"""
    total = len(items)
    ports: "queue.Queue[int]" = queue.Queue()
    for i in range(ck.WORKERS):
        ports.put(ck.BASE_PORT + i)
    lock = threading.Lock()
    done = [0]

    def task(item):
        kid, key = item
        port = ports.get()
        try:
            res = ck.check_key(key, port)
        except Exception as e:  # сбой одного ключа не должен ронять всё; такой ключ не удаляем
            log.warning("%s: непредвиденная ошибка проверки: %s", ck.label_of(key), e, exc_info=True)
            res = ck.make_result("skip", f"internal_error: {type(e).__name__}: {e}")
        finally:
            ports.put(port)
        with lock:
            done[0] += 1
            if done[0] % 50 == 0 or done[0] == total:
                log.info("прогресс проверки: %d/%d", done[0], total)
        return kid, res

    with ThreadPoolExecutor(max_workers=ck.WORKERS) as ex:
        return dict(ex.map(task, items))


async def main() -> int:
    started = time.time()
    api_id = int(need("TG_API_ID"))
    api_hash = need("TG_API_HASH")
    session = need("TG_SESSION")
    chat_raw = need("TG_CHAT")
    topic_env = int(os.getenv("TG_TOPIC_ID", "0") or 0)
    msg_limit = int(os.getenv("MSG_LIMIT", "2000"))
    dry_run = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")
    safeguard_min = int(os.getenv("SAFEGUARD_MIN", "10"))

    log.info("старт | dry_run=%s log_level=%s workers=%d timeout=%ds msg_limit=%d",
             dry_run, logging.getLevelName(logging.getLogger().level), ck.WORKERS, ck.TIMEOUT, msg_limit)
    log.info("пороги | delete_after_fails=%d ok_interval=%ds backoff=%ds x%.1f (макс %ds) "
             "state_ttl=%sд safeguard_min=%d", ks.DELETE_AFTER_FAILS, ks.OK_INTERVAL_SEC,
             ks.BACKOFF_BASE_SEC, ks.BACKOFF_FACTOR, ks.BACKOFF_MAX_SEC, ks.STATE_TTL_DAYS, safeguard_min)

    ck.engine_versions()
    if not ck.preflight():
        log.warning("У раннера нет прямого интернета, останавливаюсь, ничего не меняю")
        return 1

    now = ks.utcnow()
    state = ks.State()
    state.load()
    state.prune(now)

    async with TelegramClient(StringSession(session), api_id, api_hash) as client:
        log.debug("подключился к Telegram, загружаю диалоги")
        dialogs = await client.get_dialogs()  # чтобы Telethon узнал группу
        log.debug("диалогов загружено: %d", len(dialogs))

        chat_ref, link_topic = parse_chat(chat_raw)
        topic_id = topic_env or link_topic
        log.info("чат=%r топик=%s (из секрета: %s, из ссылки: %s)",
                 chat_ref, topic_id or "все", topic_env or "-", link_topic or "-")
        chat = await client.get_entity(chat_ref)
        log.info("чат найден: %s (id=%s)", getattr(chat, "title", chat_ref), chat.id)

        kwargs = {"limit": msg_limit}
        if topic_id:
            kwargs["reply_to"] = topic_id

        msg_keys = {}   # id сообщения -> [key_id]
        keep = set()    # сообщения с неподдерживаемыми ссылками: не удаляем
        unique = {}     # key_id -> key
        added_at = {}   # key_id -> самая ранняя дата сообщения
        scanned = 0
        async for m in client.iter_messages(chat, **kwargs):
            scanned += 1
            keys, has_unsup = extract(m)
            log.debug("сообщение %s от %s: ключей=%d, неподдерживаемые ссылки=%s",
                      m.id, ks.iso(m.date), len(keys), has_unsup)
            if has_unsup:
                keep.add(m.id)
            if not keys:
                continue
            ids = []
            for k in keys:
                kid = ck.key_id(k)
                unique.setdefault(kid, k)
                if kid not in added_at or m.date < added_at[kid]:
                    added_at[kid] = m.date
                ids.append(kid)
            msg_keys[m.id] = ids

        log.info("прочитано сообщений: %d, с ключами: %d, уникальных ключей: %d, "
                 "сообщений с неподдерживаемыми ссылками: %d",
                 scanned, len(msg_keys), len(unique), len(keep))

        # --- регистрируем ключи в состоянии и решаем, что проверять ---
        for kid, key in unique.items():
            state.touch(kid, ck.label_of(key), added_at.get(kid), now)

        to_check, skipped_alive, skipped_dead = [], 0, 0
        for kid, key in unique.items():
            rec = state.get(kid)
            if state.is_due(rec, now):
                log.debug("%s: пора проверять (next_check_at=%s)", rec["label"], rec["next_check_at"])
                to_check.append((kid, key))
            elif state.is_dead(rec):
                skipped_dead += 1
                log.debug("%s: пропуск по расписанию, считаю мёртвым | %s", rec["label"], ks.describe_full(rec))
            else:
                skipped_alive += 1
                log.debug("%s: пропуск по расписанию, считаю живым | %s", rec["label"], ks.describe_full(rec))
        log.info("к проверке: %d, пропущено по расписанию: живых %d, мёртвых %d",
                 len(to_check), skipped_alive, skipped_dead)

        # --- проверка ---
        results = await asyncio.to_thread(run_checks, to_check)
        ok_n = sum(1 for r in results.values() if r.status == "ok")
        fail_n = sum(1 for r in results.values() if r.status == "fail")
        skip_n = sum(1 for r in results.values() if r.status == "skip")
        log.info("итог проверки: рабочих %d, нерабочих %d, пропущено (формат не поддерживается) %d",
                 ok_n, fail_n, skip_n)

        # защита: много проверенных и ни один не рабочий, скорее всего проблема сети или движков
        if fail_n >= safeguard_min and ok_n == 0:
            log.warning("Подозрительный результат: %d ключей проверено, ни один не рабочий (порог %d). "
                        "Результаты не записываю, ничего не удаляю", fail_n, safeguard_min)
            state.save()
            return 1

        # --- записываем результаты в состояние ---
        for kid, res in results.items():
            lb = state.get(kid)["label"]
            if res.status == "ok":
                rec = state.record_ok(kid, res.finished_at, res.latency_ms)
                log.info("OK   %s latency=%sms | %s", lb, res.latency_ms, ks.describe(rec))
            elif res.status == "fail":
                rec = state.record_fail(kid, res.finished_at, res.error)
                log.warning("FAIL %s error=%s | %s", lb, res.error, ks.describe(rec))
            else:
                state.record_skip(kid, res.finished_at, res.error)
                log.info("SKIP %s reason=%s", lb, res.error)
        state.save()

        # --- решаем, какие сообщения удалять ---
        del_ids = []
        for mid, kids in msg_keys.items():
            if mid in keep:
                log.debug("сообщение %s: оставляю, в нём есть неподдерживаемые ссылки", mid)
                continue
            recs = [state.get(k) for k in kids]
            if all(state.is_dead(r) for r in recs):
                del_ids.append(mid)
                log.info("К УДАЛЕНИЮ: сообщение %s, ключей %d: %s", mid, len(kids),
                         ", ".join(r["label"] for r in recs))
            else:
                alive = [r["label"] for r in recs if not state.is_dead(r)]
                log.debug("сообщение %s: оставляю, не мёртвы или не проверены: %s", mid, ", ".join(alive))
        log.info("сообщений к удалению: %d", len(del_ids))

        deleted = 0
        if dry_run:
            log.info("DRY_RUN: ничего не удаляю")
        else:
            for i in range(0, len(del_ids), 100):
                chunk = del_ids[i:i + 100]
                log.debug("удаляю пачку из %d сообщений: %s", len(chunk), chunk)
                try:
                    await client.delete_messages(chat, chunk)
                except FloodWaitError as e:
                    log.warning("FloodWait: жду %d с и повторяю", e.seconds + 1)
                    await asyncio.sleep(e.seconds + 1)
                    await client.delete_messages(chat, chunk)
                except (ChatAdminRequiredError, MessageDeleteForbiddenError) as e:
                    log.warning("Нет прав на удаление: %s", e)
                    return 1
                deleted += len(chunk)
                log.info("удалено сообщений: %d/%d", deleted, len(del_ids))
                await asyncio.sleep(1)

    log.info("готово за %.1f с | прочитано=%d проверено=%d (ok=%d fail=%d skip=%d) удалено=%d%s",
             time.time() - started, scanned, len(to_check), ok_n, fail_n, skip_n, deleted,
             " (dry_run)" if dry_run else "")
    return 0


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    except SystemExit:
        raise
    except Exception as e:
        log.warning("Необработанная ошибка: %s", e, exc_info=True)
        code = 1
    sys.exit(code)
