import React, { useEffect, useState } from 'react';
import * as api from '../api/api';

const LiveAlertsFeed = () => {
    const [alerts, setAlerts] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const data = await api.fetchLiveAlerts();  // ✅ Correct usage
                setAlerts(data);
            } catch (error) {
                console.error('Error fetching alerts:', error);
            }
        };

        fetchData(); // Initial fetch
        const interval = setInterval(fetchData, 10000); // Fetch every 10s

        return () => clearInterval(interval); // Cleanup on unmount
    }, []);

    return (
        <div className="bg-zinc-900 text-white p-4 rounded-xl mt-4">
            <h2 className="text-lg font-semibold">Live Attack Feed</h2>
            <table className="w-full mt-2 text-sm">
                <thead>
                    <tr className="text-gray-300 border-b border-gray-700">
                        <th className="text-left p-1">Timestamp</th>
                        <th className="text-left p-1">Source IP</th>
                        <th className="text-left p-1">Target IP</th>
                        <th className="text-left p-1">Type</th>
                        <th className="text-left p-1">Severity</th>
                        <th className="text-left p-1">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.map((alert, i) => (
                        <tr key={i} className="border-t border-gray-700 hover:bg-zinc-800">
                            <td className="p-1">{alert.timestamp}</td>
                            <td className="p-1">{alert.source_ip}</td>
                            <td className="p-1">{alert.target_ip}</td>
                            <td className="p-1">{alert.attack_type}</td>
                            <td className="p-1">{alert.severity}</td>
                            <td className="p-1">{alert.status}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default LiveAlertsFeed;
