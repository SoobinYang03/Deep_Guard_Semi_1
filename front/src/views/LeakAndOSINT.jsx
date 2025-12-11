import React, { useState, useEffect } from 'react';
import { getLeaks } from '../services/api';
import Spinner from '../components/Spinner';
import LeakDetailModal from '../components/LeakDetailModal';
import UploadLeakModal from '../components/UploadLeakModal';

const LeakAndOSINT = () => {
  const [selectedLeak, setSelectedLeak] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [leaks, setLeaks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalLeaks, setTotalLeaks] = useState(0);
  const [filterSeverity, setFilterSeverity] = useState('');
  const [showUploadModal, setShowUploadModal] = useState(false);
  
  // 페이징 관련 상수
  const itemsPerPage = 10;
  
  // 데이터 로드
  useEffect(() => {
    loadLeaks();
  }, [currentPage, filterSeverity]);
  
  const loadLeaks = async () => {
    try {
      setLoading(true);
      const skip = (currentPage - 1) * itemsPerPage;
      const params = { limit: itemsPerPage, skip };
      if (filterSeverity) {
        params.severity = filterSeverity;
      }
      const response = await getLeaks(params);
      setLeaks(response.data.leaks);
      setTotalLeaks(response.data.total);
      setError(null);
    } catch (err) {
      setError('데이터를 불러오는데 실패했습니다.');
      console.error('Failed to load leaks:', err);
    } finally {
      setLoading(false);
    }
  };
  
  const totalPages = Math.ceil(totalLeaks / itemsPerPage);
  
  // severity를 한글 위험도로 변환
  const getSeverityLabel = (severity) => {
    const labels = {
      'critical': 'Critical',
      'high': 'High',
      'medium': 'Medium',
      'low': 'Low'
    };
    return labels[severity?.toLowerCase()] || severity || 'N/A';
  };
  
  // severity에 따른 색상
  const getSeverityColor = (severity) => {
    const colors = {
      'critical': 'text-red-500',
      'high': 'text-orange-500',
      'medium': 'text-yellow-500',
      'low': 'text-green-500'
    };
    return colors[severity?.toLowerCase()] || 'text-gray-500';
  };
  
  // source type을 한글로 변환
  const getSourceTypeLabel = (type) => {
    const labels = {
      'darkweb': '다크웹',
      'surfaceweb': '표면 웹',
      'telegram': '텔레그램'
    };
    return labels[type?.toLowerCase()] || type || 'N/A';
  };
  
  // 날짜 포맷팅
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
  };

  // 상태 라벨
  const getStatusLabel = (status) => {
    const labels = {
      'new': '신규',
      'processing': '처리중',
      'investigating': '조사중',
      'resolved': '해결됨'
    };
    return labels[status] || '신규';
  };

  // 상태 색상
  const getStatusColor = (status) => {
    const colors = {
      'new': 'bg-red-900/40 text-red-400 border-red-700/50',
      'processing': 'bg-yellow-900/40 text-yellow-400 border-yellow-700/50',
      'investigating': 'bg-blue-900/40 text-blue-400 border-blue-700/50',
      'resolved': 'bg-green-900/40 text-green-400 border-green-700/50'
    };
    return colors[status] || colors['new'];
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">보안 위협 분석</h1>
        <p className="text-gray-400">감지된 유출 정보를 분석하고 관리합니다</p>
      </div>

      <div className="bg-dark-card p-6 rounded-lg shadow-lg border border-gray-700">
        {/* 필터 바 */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-white">유출 파일 목록</h2>
          <div className="flex items-center space-x-4">
            <select
              value={filterSeverity}
              onChange={(e) => {
                setFilterSeverity(e.target.value);
                setCurrentPage(1);
              }}
              className="px-3 py-2 bg-gray-800 border border-gray-600 rounded-md text-white text-sm focus:outline-none focus:border-accent"
            >
              <option value="">전체 심각도</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button
              onClick={() => setShowUploadModal(true)}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-medium rounded-md transition flex items-center space-x-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"></path>
              </svg>
              <span>업로드</span>
            </button>
            <button
              onClick={loadLeaks}
              className="px-4 py-2 bg-accent hover:bg-cyan-600 text-dark-bg font-medium rounded-md transition flex items-center space-x-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
              </svg>
              <span>새로고침</span>
            </button>
          </div>
        </div>

        {/* 로딩 상태 */}
        {loading && (
          <div className="flex justify-center items-center py-12">
            <Spinner />
            <span className="ml-3 text-gray-400">데이터를 불러오는 중...</span>
          </div>
        )}

        {/* 에러 상태 */}
        {error && !loading && (
          <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 text-red-400 text-center">
            {error}
          </div>
        )}

        {/* 데이터 테이블 */}
        {!loading && !error && (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-700">
                <thead>
                  <tr>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">파일명</th>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">출처</th>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">유출 날짜</th>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">위험도</th>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">대응 상태</th>
                    <th className="py-3 px-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">원본 링크</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {leaks.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="py-8 text-center text-gray-500">
                        유출 정보가 없습니다.
                      </td>
                    </tr>
                  ) : (
                    leaks.map((leak) => (
                      <tr key={leak._id} className="hover:bg-gray-700/50 transition">
                        <td className="py-4 px-4 text-sm">
                          <button
                            onClick={() => setSelectedLeak(leak)}
                            className="text-blue-400 hover:text-blue-300 underline text-left"
                          >
                            {leak.files && leak.files.length > 0 ? (
                              <div>
                                <div className="font-medium">{leak.files[0].file_name}</div>
                                {leak.files.length > 1 && (
                                  <div className="text-xs text-gray-500">외 {leak.files.length - 1}개 파일</div>
                                )}
                              </div>
                            ) : (
                              <div className="text-gray-500 italic">파일 없음</div>
                            )}
                          </button>
                        </td>
                        <td className="py-4 px-4 whitespace-nowrap text-sm text-gray-300">
                          {leak.source ? (
                            <div>
                              <div className="font-medium">{leak.source.name}</div>
                              <div className="text-xs text-gray-500">{getSourceTypeLabel(leak.source.type)}</div>
                            </div>
                          ) : (
                            <span className="text-gray-500">N/A</span>
                          )}
                        </td>
                        <td className="py-4 px-4 whitespace-nowrap text-sm text-gray-300">
                          {formatDate(leak.leak_date)}
                        </td>
                        <td className={`py-4 px-4 whitespace-nowrap text-sm font-semibold ${getSeverityColor(leak.severity)}`}>
                          {getSeverityLabel(leak.severity)}
                        </td>
                        <td className="py-4 px-4 whitespace-nowrap text-sm">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(leak.status || 'new')}`}>
                            {getStatusLabel(leak.status || 'new')}
                          </span>
                        </td>
                        <td className="py-4 px-4 text-sm text-gray-300">
                          {leak.original_link ? (
                            <a
                              href={leak.original_link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-400 hover:text-blue-300 underline max-w-xs truncate block"
                              title={leak.original_link}
                            >
                              링크 열기
                            </a>
                          ) : (
                            <span className="text-gray-500">없음</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* 페이지네이션 */}
            {totalPages > 1 && (
              <div className="flex justify-center items-center gap-2 mt-6">
                <button
                  onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className={`px-4 py-2 rounded border text-sm font-medium transition ${
                    currentPage === 1 
                      ? 'bg-gray-800 text-gray-500 cursor-not-allowed border-gray-700' 
                      : 'bg-gray-900 text-white border-gray-600 hover:bg-gray-700'
                  }`}
                >
                  이전
                </button>
                
                <div className="flex gap-1">
                  {Array.from({ length: Math.min(totalPages, 5) }, (_, idx) => {
                    let pageNum;
                    if (totalPages <= 5) {
                      pageNum = idx + 1;
                    } else if (currentPage <= 3) {
                      pageNum = idx + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + idx;
                    } else {
                      pageNum = currentPage - 2 + idx;
                    }
                    
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setCurrentPage(pageNum)}
                        className={`px-3 py-2 rounded border text-sm font-medium transition ${
                          currentPage === pageNum 
                            ? 'bg-accent text-dark-bg border-accent' 
                            : 'bg-gray-900 text-white border-gray-600 hover:bg-gray-700'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                </div>
                
                <button
                  onClick={() => setCurrentPage((prev) => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className={`px-4 py-2 rounded border text-sm font-medium transition ${
                    currentPage === totalPages 
                      ? 'bg-gray-800 text-gray-500 cursor-not-allowed border-gray-700' 
                      : 'bg-gray-900 text-white border-gray-600 hover:bg-gray-700'
                  }`}
                >
                  다음
                </button>
              </div>
            )}

            {/* 통계 정보 */}
            <div className="mt-4 text-center text-sm text-gray-400">
              총 {totalLeaks}개의 유출 정보 (현재 페이지: {currentPage}/{totalPages || 1})
            </div>
          </>
        )}
      </div>

      {/* 상세 모달 */}
      <LeakDetailModal 
        leak={selectedLeak}
        onClose={() => setSelectedLeak(null)}
        onStatusUpdate={() => loadLeaks()}
      />

      {/* 업로드 모달 */}
      <UploadLeakModal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        onUploadSuccess={() => {
          loadLeaks();
          setShowUploadModal(false);
        }}
      />
    </div>
  );
};

export default LeakAndOSINT;