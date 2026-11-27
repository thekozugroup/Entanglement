"""Forward opaque UDP datagrams through a private Unix socket, optionally pacing upload."""
import asyncio, socket, sys
from pathlib import Path

async def main():
    side, name, control, front_port, rate = sys.argv[1:]
    front_port, rate = int(front_port), int(rate)
    loop = asyncio.get_running_loop()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', front_port if side == 'front' else 0))
    ipc = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    endpoint = lambda end: f'{control}/{name}-{end}.sock'
    ipc.bind(endpoint(side))
    remote = endpoint('back' if side == 'front' else 'front')
    for sock in [udp, ipc]:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF, 1024*1024)
    peer = ('127.0.0.1',7443)
    async def configure():
        nonlocal rate
        current = Path(control) / (name + '.rate')
        while True:
            if side == 'front' and current.exists():
                rate = int(current.read_text())
                marker=current.with_suffix('.observed')
                if not marker.exists() or marker.read_text()!=str(rate): marker.write_text(str(rate))
            await asyncio.sleep(.25)
    async def upload():
        nonlocal peer
        while True:
            packet, source = await loop.sock_recvfrom(udp, 65536)
            if side == 'front':
                peer = source
                if rate:
                    await asyncio.sleep(len(packet)*8/rate)
            try:
                await loop.sock_sendto(ipc, packet, remote)
            except (ConnectionRefusedError, FileNotFoundError):
                continue
    async def download():
        while True:
            data = await loop.sock_recv(ipc, 65536)
            await loop.sock_sendto(udp,data,peer)
    await asyncio.gather(upload(),download(),configure())

asyncio.run(main())
