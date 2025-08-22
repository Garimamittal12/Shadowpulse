import React, { useEffect, useState } from 'react';

const OverviewPanel = () => {
    const [gateway, setGateway] = useState("192.168.0.1");

    return (
    <div className="bg-black text-white p-4 rounded-xl shadow-xl">
    <h2 className="text-xl font-bold">Network Overview</h2>
    <div>Status: <span className="text-green-500">Online</span></div>
    <ul className="grid grid-cols-2 gap-2 mt-2">
        <li>ARP Spoofing: ❌</li>
        <li>DNS Spoofing: ✔️</li>
        <li>SSL Strip: ❌</li>
        <li>Rogue AP: ❌</li>
        <li>Gateway: {gateway}</li>
    </ul>
    </div>
    );
};

export default OverviewPanel;
