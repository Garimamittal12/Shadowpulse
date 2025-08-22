import React from 'react';

const PacketViewer = () => {
    const suspiciousPackets = [
    {
        protocol: 'HTTP',
        ttl: 21,
        payload: 'GET /index.html HTTP/1.1\r\nHost: evil.com',
    },
    ];

    return (
    <div className="bg-zinc-900 text-white p-4 rounded-xl mt-4">
        <h2 className="text-lg">Suspicious Packets</h2>
        {suspiciousPackets.map((pkt, i) => (
        <div key={i} className="border border-zinc-700 p-2 mt-2 rounded">
            <div><strong>Protocol:</strong> {pkt.protocol}</div>
            <div><strong>TTL:</strong> {pkt.ttl}</div>
            <div><strong>Payload:</strong> <pre>{pkt.payload}</pre></div>
        </div>
        ))}
    </div>
    );
};

export default PacketViewer;