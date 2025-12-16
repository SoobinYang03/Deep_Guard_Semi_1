import React from 'react';

const Header = ({ currentView, onViewChange }) => {
  const navItems = [
    { id: 'dashboard', label: '요약 보고 (Dashboard)' },
    { id: 'leakosint', label: '보안 위협 분석 (Leak & OSINT)' },
    { id: 'personalinfo', label: '개인정보 유출 검색' },
    { id: 'malware', label: '악성코드 탐지 (Malware)' },
    { id: 'portscan', label: '포트 스캐너 (Port Scanner)' },
    { id: 'settings', label: '설정' }
  ];

  return (
    <header className="flex flex-col bg-dark-card shadow-lg flex-shrink-0">
      <div className="flex items-center justify-between p-4 px-6 border-b border-gray-700">
        {/* Logo (DEEPGUARD) */}
        <div className="flex items-center space-x-2">
          <svg className="w-8 h-8 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
          </svg>
          <span className="text-xl font-extrabold text-white tracking-wider">DEEPGUARD</span>
        </div>
        
        {/* User and Actions */}
        <div className="flex items-center space-x-4">
          <button className="px-3 py-1 bg-accent hover:bg-cyan-600 text-dark-bg text-sm font-semibold rounded-md transition duration-150">
            보고서 다운로드
          </button>
          <div className="flex items-center space-x-2 cursor-pointer">
            <div className="w-8 h-8 bg-gray-600 rounded-full flex items-center justify-center text-sm font-medium">A</div>
            <span className="text-sm">adminpage@deepguard.com</span>
          </div>
        </div>
      </div>

      {/* Top Navigation Tabs */}
      <nav className="flex space-x-8 px-6 text-sm font-medium">
        {navItems.map(item => (
          <button
            key={item.id}
            className={`py-3 transition duration-150 ${
              currentView === item.id
                ? 'text-accent border-b-2 border-accent'
                : 'text-gray-400 hover:text-accent'
            }`}
            onClick={() => onViewChange(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </header>
  );
};

export default Header;
