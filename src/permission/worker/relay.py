"""Trusted in-namespace TCP-to-UDS relay. No network authority lives here."""
import asyncio
import sys


async def relay(reader, writer):
    peer_writer = None
    try:
        peer_reader, peer_writer = await asyncio.open_unix_connection('/run/kagent/broker.sock')
        async def pump(source, destination):
            try:
                while data := await source.read(16384):
                    destination.write(data)
                    await destination.drain()
            except OSError:
                pass
            finally:
                try:
                    destination.write_eof()
                except OSError:
                    pass
        await asyncio.gather(pump(reader, peer_writer), pump(peer_reader, writer))
    finally:
        writer.close()
        if peer_writer:
            peer_writer.close()


async def main():
    server = await asyncio.start_server(relay, '127.0.0.1', 18080)
    async with server:
        child = await asyncio.create_subprocess_exec(*sys.argv[1:])
        return await child.wait()


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
