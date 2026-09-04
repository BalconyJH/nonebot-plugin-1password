"""Length-prefixed canonical JSON transport secured by mutual TLS."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import struct
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from math import isfinite
from re import ASCII, compile as compile_pattern
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol, TypeAlias, TypeVar, cast

from .errors import BrokerError, BrokerErrorCode
from .protocol import (
    PROTOCOL_VERSION,
    ActionGrantProof,
    AuthenticatedClientIdentity,
    BrokerGrantRequest,
    BrokerHealthErrorCode,
    BrokerHealthRequest,
    BrokerHealthState,
    BrokerHealthView,
    BrokerJobView,
    BrokerPullRequest,
    BrokerSubmission,
    BrokerSubmissionReceipt,
    grant_proof_from_json,
    grant_request_from_json,
    health_request_from_json,
    health_view_from_json,
    job_view_from_json,
    pull_request_from_json,
    submission_from_json,
    submission_receipt_from_json,
)

if TYPE_CHECKING:
    import socket
    from asyncio import StreamReader, StreamWriter, Task
    from collections.abc import Mapping
    from pathlib import Path

    from .service import BrokerService

_FRAME_HEADER_SIZE: Final = 4
_FINGERPRINT_PATTERN = compile_pattern(r"[0-9a-f]{64}\Z", ASCII)
_HOST_LIMIT: Final = 253
_MINIMUM_FRAME_BYTES: Final = 256
_MAXIMUM_PORT: Final = 65_535
_SOCKET_ADDRESS_ITEMS: Final = 2
_HOST_PATTERN = compile_pattern(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\Z", ASCII)
_EnumT = TypeVar("_EnumT", bound=Enum)


class _ListeningServer(Protocol):
    @property
    def sockets(self) -> tuple[socket.socket, ...] | None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


class BrokerAuditWorker(Protocol):
    """Run one lifecycle-owned ordered audit outlet worker."""

    async def run(self, stop: asyncio.Event) -> None:
        """Run until the shared normal-shutdown signal is set."""
        ...


class BrokerRpcOperation(str, Enum):
    """Closed remote operations supported by the Broker transport."""

    SUBMIT = "submit"
    PULL = "pull"
    HEALTH = "health"
    GRANT = "grant"
    SYSTEM = "system"


class BrokerRpcErrorCode(str, Enum):
    """Closed wire failures; response bodies never contain exception text."""

    AUTHENTICATION_FAILED = "authentication_failed"
    INVALID_FRAME = "invalid_frame"
    FRAME_TOO_LARGE = "frame_too_large"
    INVALID_MESSAGE = "invalid_message"
    REQUEST_TIMEOUT = "request_timeout"
    INTERNAL_ERROR = "internal_error"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_PROTOCOL = "invalid_protocol"
    UNSAFE_WIRE_VALUE = "unsafe_wire_value"
    INVALID_TIME_WINDOW = "invalid_time_window"
    SUBMISSION_EXPIRED = "submission_expired"
    SUBMISSION_NOT_YET_VALID = "submission_not_yet_valid"
    GRANT_MISMATCH = "grant_mismatch"
    GRANT_UNAVAILABLE = "grant_unavailable"
    REPLAY_DETECTED = "replay_detected"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    IDENTITY_CONFLICT = "identity_conflict"
    JOB_NOT_FOUND = "job_not_found"
    JOB_STATE_CONFLICT = "job_state_conflict"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    STORE_UNAVAILABLE = "store_unavailable"
    STORE_CORRUPT = "store_corrupt"
    AUDIT_LEASE_LOST = "audit_lease_lost"
    WORKER_UNAVAILABLE = "worker_unavailable"


RpcRequestPayload: TypeAlias = (
    BrokerSubmission | BrokerPullRequest | BrokerHealthRequest | BrokerGrantRequest
)
RpcResponsePayload: TypeAlias = (
    BrokerSubmissionReceipt | BrokerJobView | BrokerHealthView | ActionGrantProof
)


@dataclass(frozen=True, slots=True, repr=False)
class BrokerRpcRequest:
    """One typed operation and its exact versioned protocol payload."""

    operation: BrokerRpcOperation
    payload: RpcRequestPayload
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Require operation and payload to be a valid closed pair."""
        _require_rpc_version(self.version)
        _require_request_shape(self.operation, self.payload)


@dataclass(frozen=True, slots=True, repr=False)
class BrokerRpcResponse:
    """One typed success payload or one closed error code, never both."""

    operation: BrokerRpcOperation
    payload: RpcResponsePayload | None = None
    error: BrokerRpcErrorCode | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        """Require a coherent operation-specific result or system error."""
        _require_rpc_version(self.version)
        _require_response_shape(self.operation, self.payload, self.error)


class BrokerProtocolCodec(Protocol):
    """Encode and decode complete canonical Broker RPC messages."""

    def encode_request(self, request: BrokerRpcRequest) -> bytes:
        """Return one canonical request frame body."""
        ...

    def decode_request(self, payload: bytes) -> BrokerRpcRequest:
        """Decode one exact canonical request frame body."""
        ...

    def encode_response(self, response: BrokerRpcResponse) -> bytes:
        """Return one canonical response frame body."""
        ...

    def decode_response(self, payload: bytes) -> BrokerRpcResponse:
        """Decode one exact canonical response frame body."""
        ...


class BrokerCodecError(ValueError):
    """A transport message is malformed without retaining its bytes."""

    def __init__(self) -> None:
        """Build one content-free codec failure."""
        super().__init__("invalid broker transport message")


class BrokerTransportUnavailableError(RuntimeError):
    """A TLS connection or framed exchange did not reach a known response."""

    def __init__(self) -> None:
        """Build one stable error without socket or TLS details."""
        super().__init__("broker transport unavailable")


class BrokerWorkerUnavailableError(RuntimeError):
    """A lifecycle-owned Broker worker terminated unexpectedly."""

    def __init__(self) -> None:
        """Build one stable failure without worker or exception details."""
        super().__init__("broker worker unavailable")


class BrokerRemoteResponseError(RuntimeError):
    """The authenticated Broker returned one closed failure response."""

    code: BrokerRpcErrorCode

    def __init__(self, code: BrokerRpcErrorCode) -> None:
        """Retain only the closed wire error code."""
        self.code = code
        super().__init__(f"broker remote error: {code.value}")


class BrokerFrameError(RuntimeError):
    """A length-prefixed frame violates configured transport bounds."""

    code: BrokerRpcErrorCode

    def __init__(self, code: BrokerRpcErrorCode) -> None:
        """Retain only a closed framing failure."""
        self.code = code
        super().__init__(f"broker frame error: {code.value}")


class CanonicalJsonBrokerCodec:
    """Strict codec whose accepted bytes exactly equal canonical re-encoding."""

    __slots__ = ()

    def encode_request(self, request: BrokerRpcRequest) -> bytes:
        """Encode one closed request envelope deterministically."""
        _require_rpc_request(request)
        return _canonical_object_bytes(
            {
                "operation": request.operation.value,
                "payload": request.payload.to_canonical_object(),
                "version": request.version,
            }
        )

    def decode_request(self, payload: bytes) -> BrokerRpcRequest:
        """Decode a canonical envelope and its operation-specific payload."""
        envelope = _decode_canonical_object(payload)
        _require_exact_keys(envelope, {"operation", "payload", "version"})
        operation = _enum_value(BrokerRpcOperation, envelope["operation"])
        if operation is BrokerRpcOperation.SYSTEM:
            raise BrokerCodecError
        version = _integer(envelope["version"])
        body = _canonical_object_bytes(_mapping(envelope["payload"]))
        request_payload = _decode_request_payload(operation, body)
        return BrokerRpcRequest(operation, request_payload, version)

    def encode_response(self, response: BrokerRpcResponse) -> bytes:
        """Encode one closed success or error envelope deterministically."""
        _require_rpc_response(response)
        return _canonical_object_bytes(
            {
                "error": None if response.error is None else response.error.value,
                "operation": response.operation.value,
                "payload": (
                    None
                    if response.payload is None
                    else response.payload.to_canonical_object()
                ),
                "version": response.version,
            }
        )

    def decode_response(self, payload: bytes) -> BrokerRpcResponse:
        """Decode a canonical response without accepting arbitrary details."""
        envelope = _decode_canonical_object(payload)
        _require_exact_keys(
            envelope,
            {"error", "operation", "payload", "version"},
        )
        operation = _enum_value(BrokerRpcOperation, envelope["operation"])
        version = _integer(envelope["version"])
        error = _optional_enum(BrokerRpcErrorCode, envelope["error"])
        raw_payload = envelope["payload"]
        response_payload = (
            None
            if raw_payload is None
            else _decode_response_payload(
                operation,
                _canonical_object_bytes(_mapping(raw_payload)),
            )
        )
        return BrokerRpcResponse(operation, response_payload, error, version)


@dataclass(frozen=True, slots=True)
class BrokerTransportTimeouts:
    """Finite connect, idle, read, and write deadlines."""

    connect: timedelta = timedelta(seconds=5)
    idle: timedelta = timedelta(seconds=30)
    read: timedelta = timedelta(seconds=5)
    write: timedelta = timedelta(seconds=5)

    def __post_init__(self) -> None:
        """Require every deadline to be finite and positive."""
        for timeout in (self.connect, self.idle, self.read, self.write):
            if timeout <= timedelta(0) or not isfinite(timeout.total_seconds()):
                raise ValueError


@dataclass(frozen=True, slots=True)
class BrokerServerTlsConfig:
    """TLS 1.3 server identity, client CA, and certificate allowlist."""

    host: str
    port: int
    certificate: Path
    private_key: Path
    client_ca: Path
    clients_by_fingerprint: Mapping[str, AuthenticatedClientIdentity]

    def __post_init__(self) -> None:
        """Validate network coordinates and deeply freeze the allowlist."""
        _require_host(self.host)
        _require_port(self.port, allow_zero=True)
        object.__setattr__(
            self,
            "clients_by_fingerprint",
            _freeze_client_allowlist(self.clients_by_fingerprint),
        )


@dataclass(frozen=True, slots=True)
class BrokerClientTlsConfig:
    """TLS 1.3 client identity and hostname-verified server trust."""

    host: str
    port: int
    server_hostname: str
    certificate: Path
    private_key: Path
    server_ca: Path

    def __post_init__(self) -> None:
        """Validate connect coordinates without weakening hostname checks."""
        _require_host(self.host)
        _require_host(self.server_hostname)
        _require_port(self.port, allow_zero=False)


@dataclass(frozen=True, slots=True)
class BrokerTransportLimits:
    """Frame bound and execution-worker polling interval."""

    maximum_frame_bytes: int = 64 * 1024
    worker_poll_interval: timedelta = timedelta(milliseconds=100)

    def __post_init__(self) -> None:
        """Require practical finite transport and polling bounds."""
        if (
            not _valid_frame_bound(self.maximum_frame_bytes)
            or not _MINIMUM_FRAME_BYTES <= self.maximum_frame_bytes <= 16 * 1024 * 1024
            or self.worker_poll_interval <= timedelta(0)
            or not isfinite(self.worker_poll_interval.total_seconds())
        ):
            raise ValueError


@dataclass(frozen=True, slots=True)
class BrokerTransportServerDependencies:
    """Explicit TLS, service, codec, worker, and bound dependencies."""

    tls: BrokerServerTlsConfig
    service: BrokerService
    audit_worker: BrokerAuditWorker | None = None
    codec: BrokerProtocolCodec = field(default_factory=CanonicalJsonBrokerCodec)
    timeouts: BrokerTransportTimeouts = field(default_factory=BrokerTransportTimeouts)
    limits: BrokerTransportLimits = field(default_factory=BrokerTransportLimits)


class BrokerTransportServer:
    """Drive authenticated RPC connections plus execution and audit workers."""

    __slots__ = (
        "_audit_worker",
        "_codec",
        "_connections",
        "_jobs_available",
        "_lifecycle_lock",
        "_limits",
        "_server",
        "_service",
        "_stop",
        "_supervision_task",
        "_timeouts",
        "_tls",
        "_worker_tasks",
        "_workers_started",
    )

    def __init__(self, dependencies: BrokerTransportServerDependencies) -> None:
        """Retain immutable server dependencies without opening sockets."""
        self._tls = dependencies.tls
        self._service = dependencies.service
        self._audit_worker = dependencies.audit_worker
        self._codec = dependencies.codec
        self._timeouts = dependencies.timeouts
        self._limits = dependencies.limits
        self._server: _ListeningServer | None = None
        self._connections: set[StreamWriter] = set()
        self._stop = asyncio.Event()
        self._jobs_available = asyncio.Event()
        self._lifecycle_lock = asyncio.Lock()
        self._worker_tasks: tuple[Task[None], ...] = ()
        self._supervision_task: Task[None] | None = None
        self._workers_started = False

    @property
    def running(self) -> bool:
        """Return whether the listening socket is active."""
        return self._server is not None

    @property
    def address(self) -> tuple[str, int]:
        """Return the actual bound address after startup."""
        server = self._server
        if server is None or not server.sockets:
            raise RuntimeError
        return _network_address(server.sockets[0].getsockname())

    async def start(self) -> None:
        """Open the TLS listener and start execution and audit workers once."""
        async with self._lifecycle_lock:
            if (
                self._server is not None
                or self._worker_tasks
                or self._supervision_task is not None
            ):
                raise RuntimeError
            self._stop = asyncio.Event()
            self._jobs_available = asyncio.Event()
            context = create_server_ssl_context(self._tls)
            self._server = await asyncio.start_server(
                self._handle_connection,
                host=self._tls.host,
                port=self._tls.port,
                ssl=context,
                ssl_handshake_timeout=self._timeouts.connect.total_seconds(),
            )
            workers = [
                asyncio.create_task(
                    self._execution_loop(),
                    name="nb1p-broker-execution",
                )
            ]
            if self._audit_worker is not None:
                workers.append(
                    asyncio.create_task(
                        self._audit_worker.run(self._stop),
                        name="nb1p-broker-audit",
                    )
                )
            self._worker_tasks = tuple(workers)
            self._workers_started = True
            self._supervision_task = asyncio.create_task(
                self._supervise_workers(self._worker_tasks),
                name="nb1p-broker-supervisor",
            )
            self._supervision_task.add_done_callback(_consume_task_exception)

    async def wait_for_worker_failure(self) -> None:
        """Wait until a required worker exits and propagate a stable failure."""
        task = self._supervision_task
        if task is None:
            raise RuntimeError
        await asyncio.shield(task)

    async def stop(self) -> None:
        """Stop acceptance, close clients, and drain workers in that order."""
        async with self._lifecycle_lock:
            self._workers_started = False
            server = self._server
            self._server = None
            if server is not None:
                server.close()
                await server.wait_closed()
            self._stop.set()
            self._jobs_available.set()
            writers = tuple(self._connections)
            for writer in writers:
                writer.close()
            await asyncio.gather(
                *(_wait_writer_closed(writer) for writer in writers),
                return_exceptions=True,
            )
            workers = self._worker_tasks
            self._worker_tasks = ()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            supervision = self._supervision_task
            self._supervision_task = None
            if supervision is not None:
                await asyncio.gather(supervision, return_exceptions=True)

    async def _handle_connection(
        self,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> None:
        self._connections.add(writer)
        try:
            identity = _peer_identity(writer, self._tls.clients_by_fingerprint)
            if identity is None:
                await self._send_error(
                    writer,
                    BrokerRpcOperation.SYSTEM,
                    BrokerRpcErrorCode.AUTHENTICATION_FAILED,
                )
                return
            while not self._stop.is_set():
                try:
                    frame = await read_frame(
                        reader,
                        maximum_bytes=self._limits.maximum_frame_bytes,
                        header_timeout=self._timeouts.idle,
                        body_timeout=self._timeouts.read,
                    )
                except asyncio.IncompleteReadError:
                    return
                except asyncio.TimeoutError:
                    await self._send_error(
                        writer,
                        BrokerRpcOperation.SYSTEM,
                        BrokerRpcErrorCode.REQUEST_TIMEOUT,
                    )
                    return
                except BrokerFrameError as error:
                    await self._send_error(
                        writer,
                        BrokerRpcOperation.SYSTEM,
                        error.code,
                    )
                    return
                try:
                    request = self._codec.decode_request(frame)
                except BrokerCodecError:
                    await self._send_error(
                        writer,
                        BrokerRpcOperation.SYSTEM,
                        BrokerRpcErrorCode.INVALID_MESSAGE,
                    )
                    return
                response = await self._dispatch(request, identity)
                await write_frame(
                    writer,
                    self._codec.encode_response(response),
                    maximum_bytes=self._limits.maximum_frame_bytes,
                    timeout=self._timeouts.write,
                )
        finally:
            self._connections.discard(writer)
            writer.close()
            await _wait_writer_closed(writer)

    async def _dispatch(
        self,
        request: BrokerRpcRequest,
        identity: AuthenticatedClientIdentity,
    ) -> BrokerRpcResponse:
        if request.operation is BrokerRpcOperation.HEALTH:
            _health_payload(request.payload)
        if not self._workers_available():
            return _worker_unavailable_response(request.operation)
        try:
            if request.operation is BrokerRpcOperation.SUBMIT:
                submission = _submission_payload(request.payload)
                result = await self._service.submit(submission, client=identity)
                self._jobs_available.set()
            elif request.operation is BrokerRpcOperation.PULL:
                result = await self._service.pull(
                    _pull_payload(request.payload),
                    client=identity,
                )
            elif request.operation is BrokerRpcOperation.HEALTH:
                result = await self._service.health()
            else:
                result = await self._service.grant(_grant_payload(request.payload))
        except BrokerError as error:
            return BrokerRpcResponse(
                operation=request.operation,
                error=_broker_error_code(error.code),
            )
        except Exception:  # noqa: BLE001 - RPC boundary reduces implementation failures.
            return BrokerRpcResponse(
                operation=request.operation,
                error=BrokerRpcErrorCode.INTERNAL_ERROR,
            )
        if not self._workers_available():
            return _worker_unavailable_response(request.operation)
        return BrokerRpcResponse(operation=request.operation, payload=result)

    async def _send_error(
        self,
        writer: StreamWriter,
        operation: BrokerRpcOperation,
        error: BrokerRpcErrorCode,
    ) -> None:
        try:
            await write_frame(
                writer,
                self._codec.encode_response(
                    BrokerRpcResponse(operation=operation, error=error)
                ),
                maximum_bytes=self._limits.maximum_frame_bytes,
                timeout=self._timeouts.write,
            )
        except (BrokerFrameError, ConnectionError, asyncio.TimeoutError):
            return

    async def _execution_loop(self) -> None:
        """Poll for work while treating every escaped service error as fatal.

        ``run_next`` may fail either before or after its durable claim.  The
        transport cannot distinguish those phases, so retrying an exception
        here could strand a running job or repeatedly block the queue head.
        Only an empty queue and the bounded wake-up timeout are retryable.
        """
        while not self._stop.is_set():
            processed = await self._service.run_next()
            if processed:
                continue
            self._jobs_available.clear()
            try:
                await asyncio.wait_for(
                    self._jobs_available.wait(),
                    timeout=self._limits.worker_poll_interval.total_seconds(),
                )
            except asyncio.TimeoutError:
                continue

    async def _supervise_workers(self, workers: tuple[Task[None], ...]) -> None:
        done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
        if self._stop.is_set():
            return
        self._workers_started = False
        cause = _worker_failure_cause(done)
        if cause is None:
            raise BrokerWorkerUnavailableError
        raise BrokerWorkerUnavailableError from cause

    def _workers_available(self) -> bool:
        return (
            self._workers_started
            and bool(self._worker_tasks)
            and all(not task.done() for task in self._worker_tasks)
        )


class AsyncioTlsBrokerTransport:
    """Open one hostname-verified mutual-TLS connection per typed exchange."""

    __slots__ = ("_codec", "_limits", "_ssl", "_timeouts", "_tls")

    def __init__(
        self,
        tls: BrokerClientTlsConfig,
        *,
        codec: BrokerProtocolCodec | None = None,
        timeouts: BrokerTransportTimeouts | None = None,
        limits: BrokerTransportLimits | None = None,
    ) -> None:
        """Build a client context without opening a network connection."""
        self._tls = tls
        self._codec = codec or CanonicalJsonBrokerCodec()
        self._timeouts = timeouts or BrokerTransportTimeouts()
        self._limits = limits or BrokerTransportLimits()
        self._ssl = create_client_ssl_context(tls)

    async def exchange(self, request: BrokerRpcRequest) -> BrokerRpcResponse:
        """Exchange one framed request and response over a fresh TLS session."""
        _require_rpc_request(request)
        writer: StreamWriter | None = None
        response: BrokerRpcResponse
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self._tls.host,
                    port=self._tls.port,
                    ssl=self._ssl,
                    server_hostname=self._tls.server_hostname,
                    ssl_handshake_timeout=self._timeouts.connect.total_seconds(),
                ),
                timeout=self._timeouts.connect.total_seconds(),
            )
            await write_frame(
                writer,
                self._codec.encode_request(request),
                maximum_bytes=self._limits.maximum_frame_bytes,
                timeout=self._timeouts.write,
            )
            frame = await read_frame(
                reader,
                maximum_bytes=self._limits.maximum_frame_bytes,
                header_timeout=self._timeouts.read,
                body_timeout=self._timeouts.read,
            )
            response = self._codec.decode_response(frame)
            _require_matching_operation(request, response)
        except BrokerCodecError:
            raise BrokerTransportUnavailableError from None
        except (
            BrokerFrameError,
            ConnectionError,
            OSError,
            ssl.SSLError,
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
        ):
            raise BrokerTransportUnavailableError from None
        finally:
            if writer is not None:
                writer.close()
                await _wait_writer_closed(writer)
        return response


async def read_frame(
    reader: StreamReader,
    *,
    maximum_bytes: int,
    header_timeout: timedelta,
    body_timeout: timedelta,
) -> bytes:
    """Read one non-empty bounded big-endian length-prefixed frame."""
    header = await asyncio.wait_for(
        reader.readexactly(_FRAME_HEADER_SIZE),
        timeout=header_timeout.total_seconds(),
    )
    length = struct.unpack(">I", header)[0]
    if length < 1:
        raise BrokerFrameError(BrokerRpcErrorCode.INVALID_FRAME)
    if length > maximum_bytes:
        raise BrokerFrameError(BrokerRpcErrorCode.FRAME_TOO_LARGE)
    return await asyncio.wait_for(
        reader.readexactly(length),
        timeout=body_timeout.total_seconds(),
    )


async def write_frame(
    writer: StreamWriter,
    payload: bytes,
    *,
    maximum_bytes: int,
    timeout: timedelta,
) -> None:
    """Write one non-empty bounded frame and wait for transport backpressure."""
    length = len(payload)
    if length < 1:
        raise BrokerFrameError(BrokerRpcErrorCode.INVALID_FRAME)
    if length > maximum_bytes:
        raise BrokerFrameError(BrokerRpcErrorCode.FRAME_TOO_LARGE)
    writer.write(struct.pack(">I", length) + payload)
    await asyncio.wait_for(writer.drain(), timeout=timeout.total_seconds())


def create_server_ssl_context(config: BrokerServerTlsConfig) -> ssl.SSLContext:
    """Create a TLS 1.3-only server requiring a CA-validated client cert."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(config.certificate), str(config.private_key))
    context.load_verify_locations(cafile=str(config.client_ca))
    return context


def create_client_ssl_context(config: BrokerClientTlsConfig) -> ssl.SSLContext:
    """Create a TLS 1.3-only client with hostname and server-CA checks."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=str(config.server_ca))
    context.load_cert_chain(str(config.certificate), str(config.private_key))
    return context


def certificate_fingerprint(certificate_der: bytes) -> str:
    """Return the canonical SHA-256 fingerprint used by the allowlist."""
    if not certificate_der:
        raise ValueError
    return hashlib.sha256(certificate_der).hexdigest()


def _peer_identity(
    writer: StreamWriter,
    allowlist: Mapping[str, AuthenticatedClientIdentity],
) -> AuthenticatedClientIdentity | None:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject):
        return None
    certificate = ssl_object.getpeercert(binary_form=True)
    if not isinstance(certificate, bytes) or not certificate:
        return None
    return allowlist.get(certificate_fingerprint(certificate))


def _freeze_client_allowlist(
    value: Mapping[str, AuthenticatedClientIdentity],
) -> Mapping[str, AuthenticatedClientIdentity]:
    frozen: dict[str, AuthenticatedClientIdentity] = {}
    for fingerprint, identity in value.items():
        _require_allowlist_entry(fingerprint, identity)
        frozen[fingerprint] = identity
    if not frozen:
        raise ValueError
    return MappingProxyType(frozen)


def _decode_request_payload(
    operation: BrokerRpcOperation,
    payload: bytes,
) -> RpcRequestPayload:
    if operation is BrokerRpcOperation.SUBMIT:
        return submission_from_json(payload)
    if operation is BrokerRpcOperation.PULL:
        return pull_request_from_json(payload)
    if operation is BrokerRpcOperation.HEALTH:
        return health_request_from_json(payload)
    if operation is BrokerRpcOperation.GRANT:
        return grant_request_from_json(payload)
    raise BrokerCodecError


def _decode_response_payload(
    operation: BrokerRpcOperation,
    payload: bytes,
) -> RpcResponsePayload:
    if operation is BrokerRpcOperation.SUBMIT:
        return submission_receipt_from_json(payload)
    if operation is BrokerRpcOperation.PULL:
        return job_view_from_json(payload)
    if operation is BrokerRpcOperation.HEALTH:
        return health_view_from_json(payload)
    if operation is BrokerRpcOperation.GRANT:
        return grant_proof_from_json(payload)
    raise BrokerCodecError


def _require_request_shape(
    operation: object,
    payload: object,
) -> None:
    valid = (
        (
            operation is BrokerRpcOperation.SUBMIT
            and isinstance(payload, BrokerSubmission)
        )
        or (
            operation is BrokerRpcOperation.PULL
            and isinstance(payload, BrokerPullRequest)
        )
        or (
            operation is BrokerRpcOperation.HEALTH
            and isinstance(payload, BrokerHealthRequest)
        )
        or (
            operation is BrokerRpcOperation.GRANT
            and isinstance(payload, BrokerGrantRequest)
        )
    )
    if not valid:
        raise TypeError


def _require_response_shape(
    operation: object,
    payload: object,
    error: object,
) -> None:
    if error is not None:
        if not isinstance(error, BrokerRpcErrorCode) or payload is not None:
            raise TypeError
        return
    valid = (
        (
            operation is BrokerRpcOperation.SUBMIT
            and isinstance(payload, BrokerSubmissionReceipt)
        )
        or (operation is BrokerRpcOperation.PULL and isinstance(payload, BrokerJobView))
        or (
            operation is BrokerRpcOperation.HEALTH
            and isinstance(payload, BrokerHealthView)
        )
        or (
            operation is BrokerRpcOperation.GRANT
            and isinstance(payload, ActionGrantProof)
        )
    )
    if not valid:
        raise TypeError


def _submission_payload(value: RpcRequestPayload) -> BrokerSubmission:
    if not isinstance(value, BrokerSubmission):
        raise TypeError
    return value


def _pull_payload(value: RpcRequestPayload) -> BrokerPullRequest:
    if not isinstance(value, BrokerPullRequest):
        raise TypeError
    return value


def _health_payload(value: RpcRequestPayload) -> BrokerHealthRequest:
    if not isinstance(value, BrokerHealthRequest):
        raise TypeError
    return value


def _grant_payload(value: RpcRequestPayload) -> BrokerGrantRequest:
    if not isinstance(value, BrokerGrantRequest):
        raise TypeError
    return value


def _broker_error_code(value: BrokerErrorCode) -> BrokerRpcErrorCode:
    try:
        return BrokerRpcErrorCode(value.value)
    except ValueError:
        return BrokerRpcErrorCode.INTERNAL_ERROR


def _require_rpc_version(value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value != PROTOCOL_VERSION
    ):
        raise ValueError


def _require_rpc_request(value: object) -> None:
    if not isinstance(value, BrokerRpcRequest):
        raise TypeError


def _require_rpc_response(value: object) -> None:
    if not isinstance(value, BrokerRpcResponse):
        raise TypeError


def _require_matching_operation(
    request: BrokerRpcRequest,
    response: BrokerRpcResponse,
) -> None:
    if response.operation not in {request.operation, BrokerRpcOperation.SYSTEM}:
        raise BrokerCodecError


def _decode_canonical_object(payload: bytes) -> dict[str, object]:
    try:
        decoded: object = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, BrokerCodecError):
        raise BrokerCodecError from None
    mapping = _mapping(decoded)
    if _canonical_object_bytes(mapping) != payload:
        raise BrokerCodecError
    return mapping


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerCodecError
        result[key] = value
    return result


def _canonical_object_bytes(value: dict[str, object]) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        raise BrokerCodecError from None
    return rendered.encode("ascii")


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BrokerCodecError
    raw = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in raw):
        raise BrokerCodecError
    return cast("dict[str, object]", raw)


def _require_exact_keys(value: dict[str, object], keys: set[str]) -> None:
    if set(value) != keys:
        raise BrokerCodecError


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerCodecError
    return value


def _enum_value(enum_type: type[_EnumT], value: object) -> _EnumT:
    if not isinstance(value, str):
        raise BrokerCodecError
    try:
        return enum_type(value)
    except ValueError:
        raise BrokerCodecError from None


def _optional_enum(enum_type: type[_EnumT], value: object) -> _EnumT | None:
    return None if value is None else _enum_value(enum_type, value)


def _require_host(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > _HOST_LIMIT
        or _HOST_PATTERN.fullmatch(value) is None
    ):
        raise ValueError


def _require_port(value: object, *, allow_zero: bool) -> None:
    minimum = 0 if allow_zero else 1
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= _MAXIMUM_PORT
    ):
        raise ValueError


async def _wait_writer_closed(writer: StreamWriter) -> None:
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, ssl.SSLError):
        return


def _valid_frame_bound(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int)


def _network_address(value: object) -> tuple[str, int]:
    if not isinstance(value, tuple):
        raise TypeError
    parts = cast("tuple[object, ...]", value)
    if len(parts) < _SOCKET_ADDRESS_ITEMS:
        raise RuntimeError
    host = parts[0]
    port = parts[1]
    if not isinstance(host, str) or isinstance(port, bool) or not isinstance(port, int):
        raise TypeError
    return host, port


def _worker_failure_cause(tasks: set[Task[None]]) -> BaseException | None:
    for task in tasks:
        if task.cancelled():
            return asyncio.CancelledError()
        error = task.exception()
        if error is not None:
            return error
    return None


def _worker_unavailable_response(
    operation: BrokerRpcOperation,
) -> BrokerRpcResponse:
    if operation is BrokerRpcOperation.HEALTH:
        return BrokerRpcResponse(
            operation=operation,
            payload=BrokerHealthView(
                BrokerHealthState.UNAVAILABLE,
                BrokerHealthErrorCode.WORKER_UNAVAILABLE,
            ),
        )
    return BrokerRpcResponse(
        operation=operation,
        error=BrokerRpcErrorCode.WORKER_UNAVAILABLE,
    )


def _consume_task_exception(task: Task[None]) -> None:
    if not task.cancelled():
        task.exception()


def _require_allowlist_entry(fingerprint: object, identity: object) -> None:
    if (
        not isinstance(fingerprint, str)
        or _FINGERPRINT_PATTERN.fullmatch(fingerprint) is None
        or not isinstance(identity, AuthenticatedClientIdentity)
    ):
        raise ValueError


__all__ = [
    "AsyncioTlsBrokerTransport",
    "BrokerAuditWorker",
    "BrokerClientTlsConfig",
    "BrokerCodecError",
    "BrokerFrameError",
    "BrokerProtocolCodec",
    "BrokerRemoteResponseError",
    "BrokerRpcErrorCode",
    "BrokerRpcOperation",
    "BrokerRpcRequest",
    "BrokerRpcResponse",
    "BrokerServerTlsConfig",
    "BrokerTransportLimits",
    "BrokerTransportServer",
    "BrokerTransportServerDependencies",
    "BrokerTransportTimeouts",
    "BrokerTransportUnavailableError",
    "BrokerWorkerUnavailableError",
    "CanonicalJsonBrokerCodec",
    "RpcRequestPayload",
    "RpcResponsePayload",
    "certificate_fingerprint",
    "create_client_ssl_context",
    "create_server_ssl_context",
    "read_frame",
    "write_frame",
]
