import React, { useState } from 'react';

const SettingsPage = () => {
    const [engineOn, setEngineOn] = useState(false);
    const [threshold, setThreshold] = useState(5);

    return (
    <div className="bg-zinc-900 text-white p-4 rounded-xl mt-4">
        <h2 className="text-lg">Settings</h2>
        <div className="mt-2">
        <label className="block mb-1">Detection Engine:</label>
        <button onClick={() => setEngineOn(!engineOn)} className="bg-purple-600 px-3 py-1 rounded">
            {engineOn ? "Stop" : "Start"}
        </button>
        </div>
        <div className="mt-4">
        <label>Threshold:</label>
        <input type="range" min="1" max="10" value={threshold} onChange={e => setThreshold(e.target.value)} className="ml-2" />
        <span className="ml-2">{threshold}</span>
        </div>
    </div>
    );
};

export default SettingsPage;