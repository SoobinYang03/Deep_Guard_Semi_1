import React, { useState } from 'react';
import { searchPersonalInfo, getLeakByIndex } from '../services/api';
import LeakDetailModal from '../components/LeakDetailModal';
import Spinner from '../components/Spinner';

const PersonalInfoLeak = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [selectedLeak, setSelectedLeak] = useState(null);
  const [error, setError] = useState(null);
  const [loadingLeak, setLoadingLeak] = useState(false);
  
  // 검색 결과 데이터
  const [esResults, setEsResults] = useState([]);
  const [indicesInfo, setIndicesInfo] = useState([]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    
    setIsSearching(true);
    setHasSearched(false);
    setError(null);
    
    try {
      const response = await searchPersonalInfo(searchQuery);
      setEsResults(response.data.elasticsearch_results || []);
      setIndicesInfo(response.data.indices_info || []);
      setHasSearched(true);
    } catch (err) {
      setError('검색 중 오류가 발생했습니다.');
      console.error('Search error:', err);
    } finally {
      setIsSearching(false);
    }
  };

  const handleViewDetail = async (indexName) => {
    setLoadingLeak(true);
    setError(null);
    
    try {
      const response = await getLeakByIndex(indexName);
      setSelectedLeak(response.data);
    } catch (err) {
      setError('유출 정보를 불러오는데 실패했습니다.');
      console.error('Load leak error:', err);
    } finally {
      setLoadingLeak(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">개인정보 유출 검색</h1>
        <p className="text-gray-400">이메일, 전화번호, 계정 정보 등의 유출 여부를 확인하세요</p>
      </div>

      {/* Search Section */}
      <div className="bg-dark-card rounded-lg shadow-lg p-6 border border-gray-700">
        <div className="space-y-4">
          {/* Search Input */}
          <div className="flex space-x-2">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="이메일, 전화번호, 사용자명 등을 입력하세요 (예: user@example.com, 010-1234-5678)"
              className="flex-1 px-4 py-3 bg-gray-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-accent"
            />
            <button
              onClick={handleSearch}
              disabled={isSearching || !searchQuery.trim()}
              className="px-6 py-3 bg-accent hover:bg-cyan-600 disabled:bg-gray-600 disabled:cursor-not-allowed text-dark-bg font-semibold rounded-md transition duration-150 flex items-center space-x-2"
            >
              {isSearching ? (
                <>
                  <Spinner />
                  <span>검색 중...</span>
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                  </svg>
                  <span>검색</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results Section */}
      {hasSearched && (
        <div className="bg-dark-card rounded-lg shadow-lg border border-gray-700">
          {/* Filter Bar */}
          <div className="p-4 border-b border-gray-700 flex items-center justify-between">
            <div className="text-lg font-semibold text-white">
              검색 결과
            </div>
            <div className="text-gray-400 text-sm">
              총 {esResults.length}개의 결과 발견
            </div>
          </div>

          {error && (
            <div className="p-4 bg-red-900/20 border-b border-red-700 text-red-400 text-center">
              {error}
            </div>
          )}

          {/* Results Table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    검색된 내용
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    유출 파일 이름
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    유출 필드
                  </th>
                  <th className="px-6 py-3 text-center text-xs font-medium text-gray-400 uppercase tracking-wider">
                    상세보기
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {esResults.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="px-6 py-8 text-center text-gray-500">
                      검색 결과가 없습니다.
                    </td>
                  </tr>
                ) : (
                  esResults.map((result, idx) => {
                    // 검색어와 일치하는 필드만 필터링
                    const matchedFields = Object.entries(result.data).filter(([key, value]) => {
                      const strValue = String(value).toLowerCase();
                      const query = searchQuery.toLowerCase();
                      return strValue.includes(query);
                    });

                    return (
                      <tr key={idx} className="hover:bg-gray-800/50 transition">
                        <td className="px-6 py-4">
                          <div className="space-y-1">
                            {matchedFields.length > 0 ? (
                              matchedFields.map(([key, value], i) => (
                                <div key={i} className="text-sm">
                                  <span className="text-gray-400">{key}:</span>{' '}
                                  <span className="text-white font-medium">{value}</span>
                                </div>
                              ))
                            ) : (
                              <div className="text-sm text-gray-500">일치하는 필드 없음</div>
                            )}
                          </div>
                          <div className="text-xs text-gray-500 mt-2">
                            Index: {result.index} | Score: {result.score?.toFixed(2)}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-white font-medium">
                            {result.index_info?.file_name || result.index}
                          </div>
                          <div className="text-xs text-gray-500 mt-1">
                            {result.index_info?.total_records?.toLocaleString() || 0}개 레코드
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {result.index_info && result.index_info.columns && (
                            <div className="flex flex-wrap gap-1">
                              {result.index_info.columns.map((col, colIdx) => (
                                <span
                                  key={colIdx}
                                  className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded text-xs"
                                  title={`타입: ${col.type}`}
                                >
                                  {col.name}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 text-center">
                          <button
                            onClick={() => handleViewDetail(result.index)}
                            disabled={loadingLeak}
                            className="text-accent hover:text-cyan-400 font-medium text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {loadingLeak ? '로딩 중...' : '상세보기'}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!hasSearched && !isSearching && (
        <div className="bg-dark-card rounded-lg shadow-lg border border-gray-700 p-12 text-center">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
          </svg>
          <h3 className="text-xl font-semibold text-gray-400 mb-2">검색을 시작하세요</h3>
          <p className="text-gray-500">이메일, 전화번호, 사용자명 등을 입력하여 유출 여부를 확인하세요</p>
        </div>
      )}

      {/* Detail Modal */}
      {selectedLeak && (
        <LeakDetailModal
          leak={selectedLeak}
          onClose={() => setSelectedLeak(null)}
        />
      )}
    </div>
  );
};

export default PersonalInfoLeak;
