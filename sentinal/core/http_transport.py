"""Reusable, killable HTTP workers. No budgets or database handles enter a child."""
from __future__ import annotations

import io
import multiprocessing
import signal
import socket
import threading
import time
import weakref
from email.message import Message
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NetworkDeadline(RuntimeError):
    pass


class NetworkCancelled(RuntimeError):
    pass


class NetworkBusy(RuntimeError):
    pass


class NetworkResponseTooLarge(RuntimeError):
    """A remote response exceeded the configured hard byte limit."""
    pass


class BufferedResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = Message()
        for key, value in headers:
            self.headers[key] = value
        self._body = io.BytesIO(body)

    def read1(self, size: int) -> bytes:
        return self._body.read(size)

    def close(self) -> None:
        self._body.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetworkDeadline('request deadline')
    return remaining


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    try:
        return parsed.scheme.lower(), (parsed.hostname or '').lower(), parsed.port
    except ValueError:
        return parsed.scheme.lower(), '', None


class _SafeRedirects(HTTPRedirectHandler):
    """Follow redirects, but never carry credentials to another origin and
    never leave HTTP(S)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme.lower() not in ('http', 'https'):
            raise HTTPError(req.full_url, code, msg, headers, fp)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(req.full_url) != _origin(new.full_url):
            for name in [key for key in (*new.headers, *new.unredirected_hdrs)
                         if key.lower() in ('authorization', 'cookie', 'proxy-authorization')]:
                new.remove_header(name)
        return new


_OPENER = None


def _opener():
    global _OPENER
    if _OPENER is None:
        _OPENER = build_opener(_SafeRedirects())
    return _OPENER


def _perform_request(connection, command: dict[str, Any]) -> None:
    request = Request(command['url'], data=command['data'], headers=command['headers'], method=command['method'])
    deadline = command['deadline']
    is_error = False
    max_bytes = command.get('max_response_bytes', 16 * 1024 * 1024)
    for attempt in range(2):
        try:
            response = _opener().open(request, timeout=_remaining(deadline))
            break
        except HTTPError as error:
            response, is_error = error, True
            break
        except URLError as error:
            reason = error.reason
            if attempt or not isinstance(reason, socket.gaierror) or reason.errno not in {socket.EAI_AGAIN, 11002}:
                raise
            time.sleep(min(0.5, _remaining(deadline)))
    with response:
        status = response.code if is_error else response.status
        headers = list(response.headers.items())
        connection.send(('headers', status, headers, str(getattr(response, 'reason', '')), is_error))
        declared = response.headers.get('Content-Length')
        if declared is not None:
            try:
                if int(declared) > max_bytes:
                    raise NetworkResponseTooLarge(f'response exceeds {max_bytes} byte limit')
            except ValueError:
                pass
        received = 0
        read = getattr(response, 'read1', response.read)
        while True:
            remaining = _remaining(deadline)
            stream = getattr(response, 'fp', None)
            if not hasattr(stream, 'raw'):
                stream = getattr(stream, 'fp', None)
            transport = getattr(getattr(stream, 'raw', None), '_sock', None)
            if transport is not None:
                transport.settimeout(remaining)
            chunk = read(65536)
            _remaining(deadline)
            if not chunk:
                connection.send(('done',))
                return
            received += len(chunk)
            if received > max_bytes:
                raise NetworkResponseTooLarge(f'response exceeds {max_bytes} byte limit')
            connection.send(('body', chunk))


def _network_worker(connection) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        while True:
            command = connection.recv()
            try:
                _perform_request(connection, command)
            except (NetworkDeadline, TimeoutError):
                connection.send(('error', 'timeout', 'request deadline'))
            except URLError as error:
                connection.send(('error', 'url', str(error.reason)))
            except NetworkResponseTooLarge as error:
                connection.send(('error', 'oversize', str(error)))
            except Exception as error:
                connection.send(('error', 'runtime', str(error)))
    except (EOFError, OSError):
        pass
    finally:
        connection.close()


class _Worker:
    def __init__(self, context, target, deadline, cancel):
        self.connection, child = context.Pipe()
        self.process = context.Process(target=target, args=(child,), name='sentinal-http', daemon=True)
        self.guard = threading.RLock()
        self.deadline, self.cancel = deadline, cancel
        self.busy, self.reason, self.disposed = True, None, False
        try:
            self.process.start()
        except BaseException:
            self.connection.close()
            self.process.close()
            raise
        finally:
            child.close()

    def stop(self, reason: str) -> None:
        with self.guard:
            if self.disposed:
                return
            self.reason = self.reason or reason
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(0.25)
                if self.process.is_alive():
                    self.process.kill()
                    self.process.join(0.25)

    def dispose(self) -> bool:
        with self.guard:
            if self.disposed:
                return True
            if self.process.is_alive():
                return False
            self.connection.close()
            self.process.join(0)
            self.process.close()
            self.disposed = True
            return True


class _State:
    def __init__(self, maximum, target):
        self.maximum, self.target = maximum, target
        self.context = multiprocessing.get_context('spawn')
        self.lock = threading.Lock()
        self.workers: list[_Worker] = []
        self.closed = threading.Event()
        self.monitor = None

    def close(self):
        self.closed.set()
        with self.lock:
            workers = list(self.workers)
        survivors = []
        for worker in workers:
            worker.stop('cancelled')
            if not worker.dispose():
                survivors.append(worker)
        if self.monitor is not None and self.monitor is not threading.current_thread():
            self.monitor.join(1)
        if survivors:
            raise RuntimeError('Unable to terminate an HTTP worker; transport remains closed')


def _supervise(state: _State) -> None:
    # Independent of the caller: even a slow parent-side cooldown write cannot
    # leave the child performing network work beyond its deadline.
    while not state.closed.wait(0.02):
        with state.lock:
            workers = list(state.workers)
        for worker in workers:
            with worker.guard:
                if worker.disposed or not worker.busy or worker.reason:
                    continue
                if worker.cancel is not None and worker.cancel.is_set():
                    worker.stop('cancelled')
                elif time.monotonic() >= worker.deadline:
                    worker.stop('deadline')
                elif not worker.process.is_alive():
                    worker.stop('crashed')


class NetworkTransport:
    def __init__(self, max_workers: int = 4, *, worker_target=_network_worker):
        self._state = _State(max(1, int(max_workers)), worker_target)
        self._finalize = weakref.finalize(self, self._state.close)

    def close(self) -> None:
        self._state.close()
        self._finalize.detach()

    def _reserve(self, deadline, cancel):
        state = self._state
        with state.lock:
            if state.closed.is_set():
                raise NetworkCancelled('transport closed')
            for worker in list(state.workers):
                with worker.guard:
                    if worker.busy:
                        continue
                    if worker.reason or not worker.process.is_alive():
                        worker.stop('crashed')
                        if worker.dispose():
                            state.workers.remove(worker)
                        continue
                    worker.busy, worker.deadline, worker.cancel = True, deadline, cancel
                    return worker
            if len(state.workers) >= state.maximum:
                raise NetworkBusy('network concurrency limit')
            worker = _Worker(state.context, state.target, deadline, cancel)
            state.workers.append(worker)
            if state.monitor is None:
                state.monitor = threading.Thread(target=_supervise, args=(state,), name='sentinal-http-deadlines', daemon=True)
                state.monitor.start()
            return worker

    @staticmethod
    def _check(worker):
        with worker.guard:
            reason = worker.reason
            if reason is None and worker.cancel is not None and worker.cancel.is_set():
                worker.stop('cancelled')
                reason = worker.reason
            if reason is None and time.monotonic() >= worker.deadline:
                worker.stop('deadline')
                reason = worker.reason
        if reason == 'deadline':
            raise NetworkDeadline('request deadline')
        if reason == 'cancelled':
            raise NetworkCancelled('scheduler stopping')
        if reason:
            raise URLError('network worker exited unexpectedly')

    def request(self, request: Request, deadline: float, cancel=None, on_headers: Callable | None = None,
                max_response_bytes: int = 16 * 1024 * 1024):
        _remaining(deadline)
        worker = self._reserve(deadline, cancel)
        complete = False
        try:
            self._check(worker)
            worker.connection.send({'url': request.full_url, 'data': request.data, 'headers': dict(request.header_items()), 'method': request.get_method(), 'deadline': deadline, 'max_response_bytes': max_response_bytes})
            chunks, response, received = [], None, 0
            while True:
                self._check(worker)
                try:
                    if not worker.connection.poll(0.02):
                        continue
                    message = worker.connection.recv()
                except (EOFError, OSError):
                    worker.stop('crashed')
                    self._check(worker)
                    raise
                self._check(worker)
                if message[0] == 'headers':
                    response = message[1:]
                    if on_headers is not None:
                        on_headers(response[0], dict(response[1]))
                elif message[0] == 'body':
                    received += len(message[1])
                    if received > max_response_bytes:
                        raise NetworkResponseTooLarge(f'response exceeds {max_response_bytes} byte limit')
                    chunks.append(message[1])
                elif message[0] == 'done':
                    if response is None:
                        raise RuntimeError('network worker returned no headers')
                    status, headers, reason, is_error = response
                    body = b''.join(chunks)
                    buffered = BufferedResponse(status, headers, body)
                    complete = True
                    if is_error:
                        raise HTTPError(request.full_url, status, reason, buffered.headers, io.BytesIO(body))
                    return buffered
                elif message[0] == 'error':
                    if message[1] == 'timeout':
                        worker.stop('deadline')
                        raise NetworkDeadline(message[2])
                    if message[1] == 'oversize':
                        # The child finished early without consuming the rest of
                        # the body; never reuse that connection or response.
                        worker.stop('oversize')
                        raise NetworkResponseTooLarge(message[2])
                    if message[1] == 'url':
                        complete = True
                        raise URLError(message[2])
                    complete = True
                    raise RuntimeError(message[2])
                else:
                    raise RuntimeError('invalid network worker response')
        finally:
            if not complete:
                worker.stop('discarded')
            with self._state.lock:
                with worker.guard:
                    worker.busy, worker.cancel = False, None
                    if worker.reason and worker.dispose():
                        if worker in self._state.workers:
                            self._state.workers.remove(worker)
