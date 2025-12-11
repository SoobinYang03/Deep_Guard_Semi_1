import React, { useState } from 'react';
import Header from './components/Header';
import Dashboard from './views/Dashboard';
import LeakAndOSINT from './views/LeakAndOSINT';
import PersonalInfoLeak from './views/PersonalInfoLeak';
import MalwareDetection from './views/MalwareDetection';
import PortScanner from './views/PortScanner';
import Settings from './views/Settings';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');

  const renderView = () => {
    switch(currentView) {
      case 'dashboard':
        return <Dashboard />;
      case 'leakosint':
        return <LeakAndOSINT />;
      case 'personalinfo':
        return <PersonalInfoLeak />;
      case 'malware':
        return <MalwareDetection />;
      case 'portscan':
        return <PortScanner />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-dark-bg">
      <Header currentView={currentView} onViewChange={setCurrentView} />
      <main className="flex-1 overflow-y-auto p-8 space-y-8">
        {renderView()}
      </main>
    </div>
  );
}

export default App;
