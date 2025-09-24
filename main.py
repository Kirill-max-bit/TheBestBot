import asyncio
import os

from loguru import logger
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties

from controler import Controller
from handlers import bot_router

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

logger.add("file.log",
           format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
           rotation="3 days",
           backtrace=True,
           diagnose=True)

logger.info("Бот инициализирован")


async def main():
    if not BOT_TOKEN:
        logger.error("Токен не задан. Добавьте BOT_TOKEN в .env.")
        raise ValueError("Токен не задан. Добавьте BOT_TOKEN в .env.")

    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher()
    dp.include_router(bot_router)

    logger.info("Бот запущен")

    controller = Controller()
    controller.logic()

    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()
        logger.info("Бот остановлен")


if __name__ == "__main__":
    asyncio.run(main())
