import asyncio
import os
import queue
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from telethon import TelegramClient
from telethon.errors import (ChatAdminRequiredError, FloodWaitError,
                             MessageDeleteForbiddenError)
from telethon.sessions import StringSession

import check_keys as ck

API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
SESSION = os.environ["TG_SESSION"]
CHAT = os.environ["TG_CHAT"]
TOPIC_ID = int(os.getenv("TG_TOPIC_ID", "0") or 0)
MSG_LIMIT = int(os.getenv("MSG_LIMIT", "2000"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")

_PRE = r"(?<![A-Za-z0-9+.\-])"  # чтобы не цеплять ss:// внутри wss://
KEY_RE = re.compile(_PRE + "(?:" + "|".join(re.escape(s) for s in ck.SCHEMES) + r")[^\s<>\"'`]+")
UNSUP_RE = re.compile(_PRE + "(?:" + "|".join(re.escape(s) for s in ck.UNSUPPORTED_SCHEMES) + ")")


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
    """items: [(key_id, key)] -> {key_id: True/False/None}"""
    ports: "queue.Queue[int]" = queue.Queue()
    for i in range(ck.WORKERS):
        ports.put(ck.BASE_PORT + i)

    def task(item):
        kid, key = item
        port = ports.get()
        try:
            return kid, ck.check_key(key, port)
        finally:
            ports.put(port)

    with ThreadPoolExecutor(max_workers=ck.WORKERS) as ex:
        return dict(ex.map(task, items))


async def main() -> int:
    dead = ck.load_cache()
    print(f"В кэше мёртвых: {len(dead)}")

    async with TelegramClient(StringSession(SESSION), API_ID, API_HASH) as client:
        await client.get_dialogs()  # чтобы Telethon узнал группу
        chat_ref, link_topic = parse_chat(CHAT)
        topic_id = TOPIC_ID or link_topic
        chat = await client.get_entity(chat_ref)
        print(f"Чат: {chat_ref}, топик: {topic_id or 'все'}")

        kwargs = {"limit": MSG_LIMIT}
        if topic_id:
            kwargs["reply_to"] = topic_id

        msg_keys = {}   # id сообщения -> [key_id]
        keep = set()    # сообщения с неподдерживаемыми ссылками: не удаляем
        unique = {}     # key_id -> key
        async for m in client.iter_messages(chat, **kwargs):
            keys, has_unsup = extract(m)
            if has_unsup:
                keep.add(m.id)
            if not keys:
                continue
            ids = []
            for k in keys:
                kid = ck.key_id(k)
                unique[kid] = k
                ids.append(kid)
            msg_keys[m.id] = ids

        to_check = [(kid, k) for kid, k in unique.items() if kid not in dead]
        print(f"Сообщений с ключами: {len(msg_keys)}, уникальных ключей: {len(unique)}, "
              f"пропущено по кэшу: {len(unique) - len(to_check)}, проверяем: {len(to_check)}")

        results = await asyncio.to_thread(run_checks, to_check)
        alive = sum(1 for v in results.values() if v is True)
        bad = sum(1 for v in results.values() if v is False)
        skipped = sum(1 for v in results.values() if v is None)
        print(f"Рабочих: {alive}, мёртвых: {bad}, не поддерживается: {skipped}")

        # защита: если из проверенных не прошёл ни один, скорее всего проблема с сетью/движками
        if (alive + bad) > 0 and alive == 0:
            print("Ни один ключ не прошёл проверку: ничего не удаляю")
            return 1

        now = time.time()
        for kid, ok in results.items():
            if ok is False:
                dead[kid] = now
        ck.save_cache(dead)

        # удаляем сообщение, только если ВСЕ ключи в нём мёртвые и нет неподдерживаемых ссылок
        del_ids = [mid for mid, kids in msg_keys.items()
                   if mid not in keep and all(k in dead for k in kids)]
        print(f"К удалению сообщений: {len(del_ids)}")

        if DRY_RUN:
            print("DRY_RUN: ничего не удаляю. Первые ID:", del_ids[:50])
            return 0

        for i in range(0, len(del_ids), 100):
            chunk = del_ids[i:i + 100]
            try:
                await client.delete_messages(chat, chunk)
            except FloodWaitError as e:
                await asyncio.sleep(e.seconds + 1)
                await client.delete_messages(chat, chunk)
            except (ChatAdminRequiredError, MessageDeleteForbiddenError) as e:
                print("Нет прав на удаление:", e)
                return 1
            await asyncio.sleep(1)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
