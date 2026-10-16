import asyncio
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import queue

from telethon import TelegramClient
from telethon.sessions import StringSession

from check_keys import (WORKERS, BASE_PORT, check_key, key_id,
                        load_cache, save_cache)

API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
SESSION = os.environ["TG_SESSION"]
CHAT = os.environ["TG_CHAT"]                      # @username или числовой id (-100...)
TOPIC_ID = os.getenv("TG_TOPIC_ID", "").strip()   # id топика; пусто = весь чат
LIMIT = int(os.getenv("MSG_LIMIT", "2000"))       # сколько последних сообщений сканировать
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

KEY_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>\"'`]+")


def extract_keys(text: str):
    return [k.rstrip(".,;)") for k in KEY_RE.findall(text or "")]


def check_all(keys):
    """Параллельная проверка через Xray. Возвращает {key_id: bool}."""
    ports = queue.Queue()
    for i in range(WORKERS):
        ports.put(BASE_PORT + i)

    def task(item):
        kid, key = item
        port = ports.get()
        try:
            return kid, check_key(key, port)
        finally:
            ports.put(port)

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        return dict(ex.map(task, keys))


async def main() -> int:
    dead = load_cache()
    print(f"В кэше мёртвых: {len(dead)}")

    async with TelegramClient(StringSession(SESSION), API_ID, API_HASH) as client:
        chat = int(CHAT) if CHAT.lstrip("-").isdigit() else CHAT
        entity = await client.get_entity(chat)

        kwargs = {"reply_to": int(TOPIC_ID)} if TOPIC_ID else {}
        messages = []  # (msg_id, [(kid, key), ...])
        async for msg in client.iter_messages(entity, limit=LIMIT, **kwargs):
            keys = extract_keys(msg.raw_text)
            if keys:
                messages.append((msg.id, [(key_id(k), k) for k in keys]))
        print(f"Сообщений с ключами: {len(messages)}")

        # уникальные ключи, которых нет в кэше мёртвых
        unique = {}
        for _, kl in messages:
            for kid, k in kl:
                if kid not in dead:
                    unique.setdefault(kid, k)
        print(f"Проверяем ключей: {len(unique)}")

        results = check_all(list(unique.items())) if unique else {}
        alive_n = sum(results.values())
        print(f"Рабочих: {alive_n}, мёртвых: {len(results) - alive_n}")

        # защита: если умерло всё — вероятно, сломан Xray/сеть
        if results and alive_n == 0:
            print("Ни один ключ не прошёл — ничего не удаляю и кэш не обновляю")
            return 1

        now = time.time()
        for kid, ok in results.items():
            if not ok:
                dead[kid] = now

        # удаляем сообщения, где ВСЕ ключи мёртвые
        to_delete = [mid for mid, kl in messages if all(kid in dead for kid, _ in kl)]
        print(f"Сообщений к удалению: {len(to_delete)}")

        if not DRY_RUN:
            for i in range(0, len(to_delete), 100):
                try:
                    await client.delete_messages(entity, to_delete[i:i + 100])
                except Exception as e:
                    print(f"Ошибка удаления: {e}")
                await asyncio.sleep(1)

    save_cache(dead)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
