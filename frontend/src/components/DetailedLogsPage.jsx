import React from 'react';

const DetailedLogsPage = () => {
    const logs = [
    {
        src: '192.168.0.2',
        dst: '192.168.0.1',
        type: 'ARP Spoofing',
        method: 'MAC Mismatch',
        packet: '0x4a3...',
    },];

    const exportCSV = () => {
    const csv = logs.map(row => Object.values(row).join(",")).join("\n");
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'shadowscythe_logs.csv';
    a.click();};

return (
    <div className="bg-zinc-900 text-white p-4 rounded-xl mt-4">
        <h2 className="text-lg">Detailed Logs</h2>
        <button onClick={exportCSV} className="bg-blue-600 p-2 rounded mt-2">Export CSV</button>
        <table className="w-full mt-2">
        <thead>
            <tr>
            <th>Source</th><th>Destination</th><th>Type</th><th>Detection</th><th>Packet</th>
    </tr>
        </thead>
        <tbody>
            {logs.map((log, i) => (
            <tr key={i} className="border-t border-gray-700">
                <td>{log.src}</td>
                <td>{log.dst}</td>
                <td>{log.type}</td>
                <td>{log.method}</td>
                <td>{log.packet}</td>
            </tr>
            ))}
        </tbody>
        </table>
    </div>
);
};

export default DetailedLogsPage;