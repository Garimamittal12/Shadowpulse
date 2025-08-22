import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import OverviewPanel from './components/OverviewPanel';
import LiveAlertsFeed from './components/LiveAlertsFeed';
import AttackTrendsGraphs from './components/AttackTrendsGraphs';
import PacketViewer from './components/PacketViewer';
import SettingsPage from './components/SettingsPage';
import './App.css';

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<OverviewPanel />} />
                <Route path="/alerts" element={<LiveAlertsFeed />} />
                <Route path="/graphs" element={<AttackTrendsGraphs />} />
                <Route path="/packets" element={<PacketViewer />} />
                <Route path="/settings" element={<SettingsPage />} />
            </Routes>
        </Router>
    );
}

export default App;
