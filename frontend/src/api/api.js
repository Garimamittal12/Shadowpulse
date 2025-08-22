import axios from 'axios';

const BASE_URL = 'http://localhost:5000/api'; // Change this to your backend address

export const fetchThreatSummary = async () => {
    const res = await axios.get(`${BASE_URL}/summary`);
    return res.data;
};

export const fetchLiveAlerts = async () => {
    const res = await axios.get(`${BASE_URL}/alerts`);
    return res.data;
};

export const fetchLogs = async () => {
    const res = await axios.get(`${BASE_URL}/logs`);
    return res.data;
};

export const toggleDetectionEngine = async (status) => {
    const res = await axios.post(`${BASE_URL}/toggle-engine`, { status });
    return res.data;
};

export const fetchTrafficStats = async () => {
    const res = await axios.get(`${BASE_URL}/traffic`);
    return res.data;
};

export const simulateTestAttack = async () => {
    const res = await axios.post(`${BASE_URL}/simulate`);
    return res.data;
};
