# Copyright 2025 Lennart Rosam <hello@takuto.de>
# Copyright 2025 Alexander Couzens <lynxis@fe80.eu>
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import traceback
from asyncio import StreamReader, StreamWriter
from typing import Dict, List
import json

from osmocom.gsup.message import GsupMessage

from banners import Banners
from baseModels import SubscriberInfo
from database import Database
from gsup.protocol.ipa_peer import IPAPeer
from gsup.protocol.osmocom_ipa import IPA
from gsup.request_dispatcher import GsupRequestDispatcher
from logtool import LogTool
from messaging import RedisMessaging


class GsupServer:
    SUPPORTED_IPA_PROTOCOLS = list(['CCM', 'OSMO'])
    SUPPORTED_IPA_EXTENSIONS = list(['GSUP'])
    SUPPORTED_IPA_MSGTS = list(['PING', 'PONG', 'ID_GET', 'ID_RESP', 'ID_ACK'])

    def __init__(self, host: str, port: int, socket_timeout: int, logger: LogTool, redis_messaging: RedisMessaging):
        self.host = host
        self.port = port
        self.socket_timeout = socket_timeout
        self.logger = logger
        self.redis_messaging = redis_messaging
        self.active_connections: Dict[str, IPAPeer] = dict()
        self.connections_pending_activation: List[str] = list()
        self.connections_pending_pings: Dict[str, int] = dict()
        self.ipa = IPA()
        self.gsup_handler = GsupRequestDispatcher(logger, Database(logger), self.active_connections)

    async def start_server(self):
        server = await asyncio.start_server(self.__handle_connection, self.host, self.port)
        asyncio.create_task(self._listen_for_subscriber_updates())
        self.logger.log(service='GSUP', level='INFO', message=f"{Banners().gsupService()}")
        self.logger.log(service='GSUP', level='INFO', message=f"GSUP server started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def __handle_connection(self, reader: StreamReader, writer: StreamWriter):
        """
        Handle incoming connection
        """
        peer_info = writer.get_extra_info('peername')
        if peer_info is None:
            await self.logger.logAsync(service='GSUP', level='ERROR', message="Peer information not available")
            writer.close()
            return

        peer_name = f"{peer_info[0]}:{peer_info[1]}"
        while True:
            clear_connections = False
            try:
                if reader.at_eof():
                    await self.logger.logAsync(service='GSUP', level='DEBUG', message="Connection closed by peer")
                    clear_connections = True
                    writer.close()
                    return

                if peer_name not in self.active_connections and peer_name not in self.connections_pending_activation:
                    await self.logger.logAsync(service='GSUP', level='DEBUG',
                                               message=f"New connection from {peer_name}.")
                    self.connections_pending_activation.append(peer_name)
                    writer.write(self.ipa.id_get())
                    await writer.drain()

                data = await asyncio.wait_for(reader.readexactly(3), timeout=self.socket_timeout)
                payload_length = int.from_bytes(data[0:2], 'big')
                try:
                    protocol = self.ipa.proto(data[2])
                except ValueError:
                    raise ValueError(f"Unsupported protocol:  {data[2]:#04x}")
                if protocol not in self.SUPPORTED_IPA_PROTOCOLS:
                    raise ValueError(f"Unsupported protocol: {protocol}")

                if protocol == 'CCM':
                    await self.__handle_ccm(reader, writer, peer_name, payload_length)
                    continue

                if protocol == 'OSMO':
                    peer = self.active_connections.get(peer_name)
                    if peer is None:
                        # This may happen if an unsupported OSMO protocol ext is received
                        # To handle this, we create a temporary peer object.
                        # The MSC peer tag is arbitrary and exists only to satisfy the IPAPeer constructor
                        peer = IPAPeer(peer_name, {'UNIT': 'msc'}, reader, writer)
                    await self.__handle_gsup(peer, payload_length)
                    continue
            except ValueError as e:
                await self.logger.logAsync(service='GSUP', level='ERROR',
                                           message=f"{peer_name}: {e}. Closing connection.")
                writer.close()
                clear_connections = True
                return

            except asyncio.TimeoutError:
                await self.logger.logAsync(service='GSUP', level='ERROR',
                                           message=f"Timeout reading data from peer: {peer_name}")
                writer.close()
                clear_connections = True
                return


            except (ConnectionResetError, asyncio.IncompleteReadError):
                await self.logger.logAsync(service='GSUP', level='INFO',
                                           message=f"GSUP Client disconnected: {peer_name}")
                writer.close()
                clear_connections = True
                return

            except Exception as e:
                await self.logger.logAsync(service='GSUP', level='ERROR',
                                           message=f"Error handling connection: {str(e)} trace: {traceback.format_exc()}")
                writer.close()
                clear_connections = True
                return
            finally:
                if clear_connections:
                    if peer_name in self.active_connections:
                        del self.active_connections[peer_name]
                    if peer_name in self.connections_pending_activation:
                        self.connections_pending_activation.remove(peer_name)
                    if peer_name in self.connections_pending_pings:
                        del self.connections_pending_pings[peer_name]

    async def __handle_ccm(self, reader: StreamReader, writer: StreamWriter, peer: str, payload_length: int):
        data = await asyncio.wait_for(reader.readexactly(payload_length), timeout=self.socket_timeout)
        message_type = self.ipa.msgt(data[0])

        if message_type not in self.SUPPORTED_IPA_MSGTS:
            raise ValueError(f"Unsupported message type: {message_type}")

        if peer in self.connections_pending_activation and message_type == 'PING':
            self.connections_pending_pings[peer] = self.connections_pending_pings.get(peer, 0) + 1
            return

        if peer not in self.active_connections and message_type != 'ID_RESP':
            await self.logger.logAsync(service='GSUP', level='ERROR',
                                       message=f"Client message received without known identity {peer}")
            return

        if message_type == 'ID_RESP' and peer not in self.connections_pending_activation:
            await self.logger.logAsync(service='GSUP', level='ERROR',
                                       message=f"Received ID_RESP from {peer} without pending activation")
            raise ValueError("Received ID_RESP from peer without pending activation")

        if message_type == 'ID_RESP':
            await self.__handle_ccm_identity_response(reader, writer, peer, data[1:])
            return

        if message_type == 'PING':
            await self.logger.logAsync(service='GSUP', level='DEBUG', message="Received PING message")
            writer.write(self.ipa.pong())
            await writer.drain()
            return

        await self.logger.logAsync(service='GSUP', level='WARN', message=f"Unimplemented message type: {message_type}")

    async def __handle_ccm_identity_response(self, reader: StreamReader, writer: StreamWriter, peer_name: str,
                                             payload: bytes):
        tags = {}
        index = 0
        while index < len(payload):
            try:
                length = int.from_bytes(payload[index:index + 2], 'big') - 1
                tag = self.ipa.idtag(payload[index + 2:index + 3][0])
                value = str(payload[index + 3:index + 3 + length], 'utf-8')

                if value.endswith("\0"):
                    value = value.removesuffix("\0")

                tags[tag] = value
                index += 3 + length
            except Exception as e:
                await self.logger.logAsync(service='GSUP', level='ERROR',
                                           message=f"Error parsing ID_RESP payload: {str(e)}")
                writer.close()

        peer = IPAPeer(peer_name, tags, reader, writer)
        self.active_connections[peer_name] = peer
        await self.logger.logAsync(service='GSUP', level='INFO',
                                   message=f"New peer connected: {peer}")
        writer.write(self.ipa.id_ack())
        self.connections_pending_activation.remove(peer_name)

        if peer_name in self.connections_pending_pings:
            for _ in range(self.connections_pending_pings[peer_name]):
                writer.write(self.ipa.pong())
            del self.connections_pending_pings[peer_name]

        await writer.drain()

    async def __handle_gsup(self, peer: IPAPeer, payload_length: int):
        data = await asyncio.wait_for(peer.reader.readexactly(payload_length), timeout=self.socket_timeout)
        ext = self.ipa.ext(data[0])
        if ext not in self.SUPPORTED_IPA_EXTENSIONS:
            raise ValueError(f"Unsupported OSMOCOM EXT protocol: {ext}")

        request = GsupMessage.from_bytes(data[1:])
        if request is None:
            raise ValueError(f"Error parsing GSUP message from peer {peer}")
        await self.gsup_handler.dispatch(peer, request)

    async def _listen_for_subscriber_updates(self):
        """
        Listens for subscriber update events on a Redis queue and processes them.
        """
        await self.logger.logAsync(service='GSUP', level='INFO', message="Listening for subscriber updates")
        while True:
            try:
                _, message_data = await asyncio.to_thread(self.redis_messaging.awaitMessage, 'subscriber_update')
                update_data = json.loads(message_data)
                update_event = SubscriberInfo(**update_data)

                await self.logger.logAsync(service='GSUP', level='INFO',
                                           message=f"Received subscriber update for IMSI {update_event.imsi} with new MSISDN {update_event.msisdn}")
                await self.gsup_handler.dispatch_subscriber_update(update_event)

            except Exception as e:
                await self.logger.logAsync(service='GSUP', level='ERROR',
                                           message=f"Error processing subscriber update: {traceback.format_exc()}")
