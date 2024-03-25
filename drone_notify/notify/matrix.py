import logging

from html2text import HTML2Text
from mautrix.client import Client, ClientAPI
from mautrix.client.state_store import MemorySyncStore
from mautrix.client.state_store.asyncpg.upgrade import upgrade_table
from mautrix.crypto import OlmMachine, PgCryptoStateStore, PgCryptoStore
from mautrix.errors import WellKnownError
from mautrix.types import (
    EventType,
    Format,
    MessageType,
    RoomID,
    TextMessageEventContent,
    UserID,
)
from mautrix.util.async_db import Database, SQLiteDatabase
from yarl import URL

from drone_notify.config import MatrixBotConfig, MatrixNotifyConfig
from drone_notify.notify import Bot, Notifier

log = logging.getLogger(__name__)

PICKLE_KEY = "drone-notify.crypto"


class MatrixBot(Bot):
    client: Client
    crypto: OlmMachine
    homeserver: URL

    def __init__(self, name: str, cfg: MatrixBotConfig) -> None:
        self.mxid = cfg.mxid
        _, self.domain = ClientAPI.parse_user_id(UserID(self.mxid))
        self.access_token = cfg.access_token
        self.db_path = cfg.db_path

        self.sync_store = MemorySyncStore()
        self.database: Database = SQLiteDatabase(url=URL(self.db_path), upgrade_table=upgrade_table)
        self.state_store = PgCryptoStateStore(self.database)
        self.crypto_store = PgCryptoStore(
            account_id=self.mxid, pickle_key=PICKLE_KEY, db=self.database
        )

        super().__init__(name, cfg)

    async def start(self) -> None:
        # Setup and upgrade database schema
        await self.database.start()
        await self.crypto_store.upgrade_table.upgrade(self.database)
        await self.state_store.upgrade_table.upgrade(self.database)

        hs = await ClientAPI.discover(self.domain)
        if hs is None:
            raise WellKnownError("Failed to discover Matrix homeserver URL")

        self.client = Client(
            self.mxid,
            token=self.access_token,
            base_url=hs,
            state_store=self.state_store,
            sync_store=self.sync_store,
        )
        self.client.crypto = OlmMachine(
            client=self.client,
            crypto_store=self.crypto_store,
            state_store=self.state_store,
        )

        whoiam = await self.client.whoami()
        assert whoiam.device_id is not None
        assert whoiam.user_id == self.mxid, f"mxid differs: {whoiam.user_id} != {self.mxid}"
        if not self.client.device_id:
            self.client.device_id = whoiam.device_id

        # Set up crypto
        await self.crypto_store.open()

        crypto_device_id = await self.crypto_store.get_device_id()
        log.info("crypto_store device_id is: %s", crypto_device_id)
        if crypto_device_id and crypto_device_id != self.client.device_id:
            log.warning("Resetting crypto store as device-id differs")
            await self.crypto_store.delete()
        await self.client.crypto.load()
        if not crypto_device_id:
            await self.crypto_store.put_device_id(self.client.device_id)

        # Start sync'ing to get to-device events and to set up crypto keys
        self.client.start(None)

        log.info("Initialised Matrix bot %s (%s)", self.name, self.mxid)

    async def stop(self) -> None:
        self.client.stop()
        await self.database.stop()


class MatrixNotifier(Notifier):
    bot: MatrixBot
    room_id: RoomID

    def __init__(self, name: str, bot: MatrixBot, cfg: MatrixNotifyConfig):
        self.room_id = cfg.room_id
        self.h2t = HTML2Text()
        super().__init__(name, bot, cfg)

    async def send(self, message: str) -> None:
        await self.bot.client.send_message_event(
            room_id=self.room_id,
            event_type=EventType.ROOM_MESSAGE,
            content=TextMessageEventContent(
                msgtype=MessageType.NOTICE,
                body=self.h2t.handle(message),
                format=Format.HTML,
                formatted_body=message,
            ),
        )
