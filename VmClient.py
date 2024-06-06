import json
import datetime
import sys
from typing import Union, Tuple, Any

import aiohttp
import logging

from eth_account import Account
from eth_account.messages import encode_defunct
from jwcrypto import jwk
from jwcrypto.jwa import JWA
from aleph.sdk.conf import settings

logger = logging.getLogger(__name__)


class InstanceManager:
    def __init__(self, private_key: str = settings.PRIVATE_KEY_STRING, domain: str = "tartaglia.aleph-power.com"):
        self.private_key = private_key
        self.account = Account.from_key(private_key)
        self.ephemeral_key = jwk.JWK.generate(kty="EC", crv="P-256")
        self.expected_domain = domain
        self.pubkey_payload = self._generate_pubkey_payload()
        self.pubkey_signature_header = self._generate_pubkey_signature_header()
        self.session = aiohttp.ClientSession()

    def _generate_pubkey_payload(self):
        return {
            "pubkey": json.loads(self.ephemeral_key.export_public()),
            "alg": "ECDSA",
            "domain":
                self.expected_domain,
            "address": self.account.address,
            "expires": (datetime.datetime.utcnow() + datetime.timedelta(days=1)).isoformat() + "Z",
        }

    def _generate_pubkey_signature_header(self):
        pubkey_payload = json.dumps(self.pubkey_payload).encode("utf-8").hex()
        signable_message = encode_defunct(hexstr=pubkey_payload)
        signed_message = self.account.sign_message(signable_message)
        pubkey_signature = self.to_0x_hex(signed_message.signature)
        return json.dumps(
            {
                "payload": pubkey_payload,
                "signature": pubkey_signature,
                "content": {
                    "domain": self.expected_domain
                }
            }
        )

    @staticmethod
    def to_0x_hex(b: bytes) -> str:
        return "0x" + bytes.hex(b)

    @staticmethod
    def on_message(content):
        try:
            msg = json.loads(content)
            fd = sys.stderr if msg["type"] == "stderr" else sys.stdout
            logger.info(f"< {msg['message']}")
        except Exception as e:
            logger.error(f"Unable to parse content: {content}, Error: {str(e)}")

    async def perform_operation(self, vm_id, operation):
        hostname = f"https://{self.expected_domain}"
        path = f"/control/machine/{vm_id}/{operation}"

        payload = {"time": datetime.datetime.utcnow().isoformat() + "Z", "method": "POST", "path": path}
        payload_as_bytes = json.dumps(payload).encode("utf-8")
        headers = {"X-SignedPubKey": self.pubkey_signature_header}
        payload_signature = JWA.signing_alg("ES256").sign(self.ephemeral_key, payload_as_bytes)
        headers["X-SignedOperation"] = json.dumps(
            {
                "payload": payload_as_bytes.hex(),
                "signature": payload_signature.hex(),
            }
        )

        url = f"{hostname}{path}"

        try:
            async with self.session.post(url, headers=headers) as response:
                response_text = await response.text()
                return response.status, response_text
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during operation {operation}: {str(e)}")
            return None, str(e)

    async def get_logs(self, vm_id):
        ws_url = f"https://{self.expected_domain}/control/machine/{vm_id}/logs"

        payload = {
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "method": "GET",
            "path": f"/control/machine/{vm_id}/logs"
        }
        payload_as_bytes = json.dumps(payload).encode("utf-8")
        headers = {"X-SignedPubKey": self.pubkey_signature_header}
        payload_signature = JWA.signing_alg("ES256").sign(self.ephemeral_key, payload_as_bytes)
        headers["X-SignedOperation"] = json.dumps(
            {
                "payload": payload_as_bytes.hex(),
                "signature": payload_signature.hex(),
            }
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url) as ws:
                    logger.error(f"Connecting to WebSocket URL: {ws_url}")

                    auth_message = {
                        "auth": {
                            "X-SignedPubKey": headers["X-SignedPubKey"],
                            "X-SignedOperation": headers["X-SignedOperation"],
                        }
                    }
                    logger.error(f"Sending auth message: {auth_message}")
                    await ws.send_json(auth_message)
                    response = await ws.receive()
                    logger.error(response.data)
        except Exception as e:
            logger.error(f"error : {e}")

    async def get_logs_as_text(self, vm_id):
        logs = []

        async def collect_logs(content):
            try:
                msg = json.loads(content)
                logs.append(msg['message'])
            except Exception as e:
                logger.error(f"Unable to parse content: {content}, Error: {str(e)}")

        original_on_message = self.on_message
        self.on_message = collect_logs

        await self.get_logs(vm_id)

        self.on_message = original_on_message
        return "\n".join(logs)

    async def start_instance(self, vm_id):
        return await self.notify_allocation(vm_id)

    async def stop_instance(self, vm_id):
        return await self.perform_operation(vm_id, "stop")

    async def reboot_instance(self, vm_id):

        return await self.perform_operation(vm_id, "reboot")

    async def erase_instance(self, vm_id):
        return await self.perform_operation(vm_id, "erase")

    async def expire_instance(self, vm_id):
        return await self.perform_operation(vm_id, "expire")

    async def notify_allocation(self, vm_id) -> tuple[Any, str]:
        json_data = {"instance": vm_id}
        try:
            async with self.session.post(f"https://{self.expected_domain}/control/allocation/notify",
                                         json=json_data) as s:
                form_response_text = await s.text()
                return s.status, form_response_text
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during allocation notification: {str(e)}")

    async def manage_instance(self, vm_id, operations):
        for operation in operations:
            logger.info(f"Performing operation: {operation}")
            status, response = await self.perform_operation(vm_id, operation)
            if status != 200:
                return status, response
        return

    async def close(self):
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()