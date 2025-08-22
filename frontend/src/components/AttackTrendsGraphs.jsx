import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell } from 'recharts';

const dummyLineData = [
    { name: '12PM', attacks: 2 },
    { name: '1PM', attacks: 5 },
    { name: '2PM', attacks: 1 },
];

const dummyPieData = [
    { name: 'ARP', value: 3 },
    { name: 'DNS', value: 2 },
    { name: 'SSL Strip', value: 1 },
];

const COLORS = ['#0088FE', '#00C49F', '#FF8042'];

const AttackTrendsGraphs = () => {
    return (
    <div className="grid grid-cols-2 gap-4 mt-4">
    <div className="bg-zinc-900 p-4 rounded-xl text-white">
        <h2>Attacks Over Time</h2>
        <LineChart width={400} height={200} data={dummyLineData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="attacks" stroke="#8884d8" activeDot={{ r: 8 }} />
        </LineChart>
        </div>
        <div className="bg-zinc-900 p-4 rounded-xl text-white">
        <h2>Attack Frequency by Type</h2>
        <PieChart width={400} height={200}>
            <Pie data={dummyPieData} cx="50%" cy="50%" label outerRadius={80} fill="#8884d8" dataKey="value">
            {dummyPieData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
            </Pie>
            <Tooltip />
        </ PieChart>
        </div>
    </div>
    );
};

export default AttackTrendsGraphs;

