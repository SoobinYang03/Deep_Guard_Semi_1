import React, { useState } from 'react';
import Spinner from '../components/Spinner';

const PortScanner = () => {
  const [targetIp, setTargetIp] = useState('220.112.55.123');
  const [scanStatus, setScanStatus] = useState('스캔 대기 중...');
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  const simulateScanResults = (ip) => {
    const allPorts = [
      { port: 21, service: 'FTP', status: 'OPEN', severity: 'caution' },
      { port: 22, service: 'SSH', status: 'OPEN', severity: 'safe' },
      { port: 23, service: 'Telnet', status: 'CLOSED', severity: 'safe' },
      { port: 80, service: 'HTTP', status: 'OPEN', severity: 'safe' },
      { port: 443, service: 'HTTPS', status: 'OPEN', severity: 'safe' },
      { port: 3306, service: 'MySQL', status: 'OPEN', severity: 'danger' },
      { port: 8080, service: 'HTTP-Alt', status: 'OPEN', severity: 'caution' },
    ];

    return allPorts.filter(r => Math.random() > 0.3 || r.status === 'OPEN');
  };

  const startPortScan = () => {
    if (!targetIp) {
      setScanStatus('대상 IP 주소를 입력해 주세요.');
      setScanResults([]);
      return;
    }

    setIsScanning(true);
    setScanStatus('스캐닝 중... (최대 10초 소요)');
    setScanResults([]);

    setTimeout(() => {
      const results = simulateScanResults(targetIp);
      setScanResults(results);
      setScanStatus(`스캔 완료. 총 ${results.length}개의 포트가 열려 있습니다.`);
      setIsScanning(false);
    }, 3000);
  };

  const getRecommendation = (severity) => {
    switch(severity) {
      case 'danger':
        return '즉시 확인 필요';
      case 'caution':
        return '보안 설정 권고';
      default:
        return '정상 작동';
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'danger':
        return 'text-danger';
      case 'caution':
        return 'text-caution';
      default:
        return 'text-safe';
    }
  };

  return (
    <section>
      <h1 className="text-3xl font-bold mb-6 text-white">포트 스캐너 (Port Scanner)</h1>
      
      <div className="bg-dark-card p-6 rounded-xl shadow-2xl space-y-6">
        <h2 className="text-xl font-semibold">대상 IP/도메인 포트 개방 상태 확인</h2>
        <p className="text-sm text-gray-400">대상 서버의 열린 포트를 탐지하여 잠재적인 네트워크 취약점을 식별합니다.</p>
        
        <div className="flex space-x-4">
          <input 
            type="text" 
            placeholder="대상 IP 주소 또는 도메인 입력 (예: 192.168.1.1)" 
            className="flex-1 p-3 bg-dark-bg border border-gray-600 rounded-lg focus:ring-accent focus:border-accent text-sm"
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
          />
          <button 
            onClick={startPortScan}
            className="px-6 py-3 bg-accent hover:bg-cyan-600 text-dark-bg font-bold rounded-lg transition duration-150"
          >
            스캔 시작
          </button>
        </div>

        <div className="mt-4 text-sm text-gray-400 flex items-center">
          {isScanning && <Spinner />}
          <span className={isScanning ? 'ml-2' : ''}>{scanStatus}</span>
        </div>

        <div className="mt-6">
          <h3 className="font-medium text-lg mb-4">스캔 분석 결과 테이블</h3>
          <table className="min-w-full divide-y divide-gray-700">
            <thead>
              <tr>
                <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">포트 번호</th>
                <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">서비스</th>
                <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">상태</th>
                <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">위험도</th>
                <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">조치 권고</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scanResults.length === 0 ? (
                <tr className="text-center">
                  <td colSpan="5" className="py-8 text-gray-500">
                    스캔을 시작하면 결과가 여기에 표시됩니다.
                  </td>
                </tr>
              ) : (
                scanResults.map((result, index) => (
                  <tr key={index} className="hover:bg-gray-700/50">
                    <td className="py-3 px-4 whitespace-nowrap text-sm">{result.port}</td>
                    <td className="py-3 px-4 whitespace-nowrap text-sm text-gray-400">{result.service}</td>
                    <td className={`py-3 px-4 whitespace-nowrap text-sm ${getSeverityColor(result.severity)} font-medium`}>
                      {result.status}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-sm text-gray-400">{result.severity}</td>
                    <td className="py-3 px-4 whitespace-nowrap text-sm text-gray-400">
                      {getRecommendation(result.severity)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};

export default PortScanner;
