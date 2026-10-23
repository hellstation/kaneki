"""
Telegram bot entry point.
"""

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.storage.redis import RedisStorage
from dotenv import load_dotenv

from .access import AccessControlMiddleware
from .handlers import router
from .rate_limit import configure_redis

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")

if not TOKEN:
    raise ValueError("BOT_TOKEN not found in .env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _build_storage():
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        return MemoryStorage()
    try:
        import redis

        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        configure_redis(client)
        logger.info("Using Redis FSM storage and rate limits")
        return RedisStorage.from_url(redis_url)
    except Exception:
        logger.exception("REDIS_URL set but Redis unavailable; using in-memory storage")
        return MemoryStorage()


async def main() -> None:
    bot = Bot(token=TOKEN)
    dp = Dispatcher(storage=_build_storage())
    dp.message.middleware(AccessControlMiddleware())
    dp.callback_query.middleware(AccessControlMiddleware())
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error("Bot failed: %s", e)
        raise
