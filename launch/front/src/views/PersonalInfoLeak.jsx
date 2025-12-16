// import React, { useState } from 'react';
// import { searchPersonalInfo, getLeakByIndex } from '../services/api';
// import LeakDetailModal from '../components/LeakDetailModal';
// import Spinner from '../components/Spinner';
//
// const PersonalInfoLeak = () => {
//   const [searchQuery, setSearchQuery] = useState('');
//   const [isSearching, setIsSearching] = useState(false);
//   const [hasSearched, setHasSearched] = useState(false);
//   const [selectedLeak, setSelectedLeak] = useState(null);
//   const [error, setError] = useState(null);
//   const [loadingLeak, setLoadingLeak] = useState(false);
//
//   // 검색 결과 데이터
//   const [esResults, setEsResults] = useState([]);
//   const [indicesInfo, setIndicesInfo] = useState([]);
//
//   const handleSearch = async () => {
//     if (!searchQuery.trim()) return;
//
//     setIsSearching(true);
//     setHasSearched(false);
//     setError(null);
//
//     try {
//       const response = await searchPersonalInfo(searchQuery);
//       setEsResults(response.data.elasticsearch_results || []);
//       setIndicesInfo(response.data.indices_info || []);
//       setHasSearched(true);
//     } catch (err) {
//       setError('검색 중 오류가 발생했습니다.');
//       console.error('Search error:', err);
//     } finally {
//       setIsSearching(false);
//     }
//   };
//
//   const handleViewDetail = async (indexName) => {
//     setLoadingLeak(true);
//     setError(null);
//
//     try {
//       const response = await getLeakByIndex(indexName);
//       setSelectedLeak(response.data);
//     } catch (err) {
//       setError('유출 정보를 불러오는데 실패했습니다.');
//       console.error('Load leak error:', err);
//     } finally {
//       setLoadingLeak(false);
//     }
//   };
//
//   const handleKeyPress = (e) => {
//     if (e.key === 'Enter') {
//       handleSearch();
//     }
//   };
//
//   const formatDate = (dateString) => {
//     if (!dateString) return 'N/A';
//     const date = new Date(dateString);
//     return date.toLocaleDateString('ko-KR', {
//       year: 'numeric',
//       month: '2-digit',
//       day: '2-digit'
//     });
//   };
//
//   return (
//     <div className="space-y-6">
//       {/* Header */}
//       <div>
//         <h1 className="text-3xl font-bold text-white mb-2">개인정보 유출 검색</h1>
//         <p className="text-gray-400">이메일, 전화번호, 계정 정보 등의 유출 여부를 확인하세요</p>
//       </div>
//
//       {/* Search Section */}
//       <div className="bg-dark-card rounded-lg shadow-lg p-6 border border-gray-700">
//         <div className="space-y-4">
//           {/* Search Input */}
//           <div className="flex space-x-2">
//             <input
//               type="text"
//               value={searchQuery}
//               onChange={(e) => setSearchQuery(e.target.value)}
//               onKeyPress={handleKeyPress}
//               placeholder="이메일, 전화번호, 사용자명 등을 입력하세요 (예: user@example.com, 010-1234-5678)"
//               className="flex-1 px-4 py-3 bg-gray-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-accent"
//             />
//             <button
//               onClick={handleSearch}
//               disabled={isSearching || !searchQuery.trim()}
//               className="px-6 py-3 bg-accent hover:bg-cyan-600 disabled:bg-gray-600 disabled:cursor-not-allowed text-dark-bg font-semibold rounded-md transition duration-150 flex items-center space-x-2"
//             >
//               {isSearching ? (
//                 <>
//                   <Spinner />
//                   <span>검색 중...</span>
//                 </>
//               ) : (
//                 <>
//                   <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//                     <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
//                   </svg>
//                   <span>검색</span>
//                 </>
//               )}
//             </button>
//           </div>
//         </div>
//       </div>
//
//       {/* Results Section */}
//       {hasSearched && (
//         <div className="bg-dark-card rounded-lg shadow-lg border border-gray-700">
//           {/* Filter Bar */}
//           <div className="p-4 border-b border-gray-700 flex items-center justify-between">
//             <div className="text-lg font-semibold text-white">
//               검색 결과
//             </div>
//             <div className="text-gray-400 text-sm">
//               총 {esResults.length}개의 결과 발견
//             </div>
//           </div>
//
//           {error && (
//             <div className="p-4 bg-red-900/20 border-b border-red-700 text-red-400 text-center">
//               {error}
//             </div>
//           )}
//
//           {/* Results Table */}
//           <div className="overflow-x-auto">
//             <table className="w-full">
//               <thead className="bg-gray-800/50">
//                 <tr>
//                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
//                     검색된 내용
//                   </th>
//                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
//                     유출 파일 이름
//                   </th>
//                   <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
//                     유출 필드
//                   </th>
//                   <th className="px-6 py-3 text-center text-xs font-medium text-gray-400 uppercase tracking-wider">
//                     상세보기
//                   </th>
//                 </tr>
//               </thead>
//               <tbody className="divide-y divide-gray-700">
//                 {esResults.length === 0 ? (
//                   <tr>
//                     <td colSpan="4" className="px-6 py-8 text-center text-gray-500">
//                       검색 결과가 없습니다.
//                     </td>
//                   </tr>
//                 ) : (
//                   esResults.map((result, idx) => {
//                     // 검색어와 일치하는 필드만 필터링
//                     const matchedFields = Object.entries(result.data).filter(([key, value]) => {
//                       const strValue = String(value).toLowerCase();
//                       const query = searchQuery.toLowerCase();
//                       return strValue.includes(query);
//                     });
//
//                     return (
//                       <tr key={idx} className="hover:bg-gray-800/50 transition">
//                         <td className="px-6 py-4">
//                           <div className="space-y-1">
//                             {matchedFields.length > 0 ? (
//                               matchedFields.map(([key, value], i) => (
//                                 <div key={i} className="text-sm">
//                                   <span className="text-gray-400">{key}:</span>{' '}
//                                   <span className="text-white font-medium">{value}</span>
//                                 </div>
//                               ))
//                             ) : (
//                               <div className="text-sm text-gray-500">일치하는 필드 없음</div>
//                             )}
//                           </div>
//                           <div className="text-xs text-gray-500 mt-2">
//                             Index: {result.index} | Score: {result.score?.toFixed(2)}
//                           </div>
//                         </td>
//                         <td className="px-6 py-4">
//                           <div className="text-white font-medium">
//                             {result.index_info?.file_name || result.index}
//                           </div>
//                           <div className="text-xs text-gray-500 mt-1">
//                             {result.index_info?.total_records?.toLocaleString() || 0}개 레코드
//                           </div>
//                         </td>
//                         <td className="px-6 py-4">
//                           {result.index_info && result.index_info.columns && (
//                             <div className="flex flex-wrap gap-1">
//                               {result.index_info.columns.map((col, colIdx) => (
//                                 <span
//                                   key={colIdx}
//                                   className="px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded text-xs"
//                                   title={`타입: ${col.type}`}
//                                 >
//                                   {col.name}
//                                 </span>
//                               ))}
//                             </div>
//                           )}
//                         </td>
//                         <td className="px-6 py-4 text-center">
//                           <button
//                             onClick={() => handleViewDetail(result.index)}
//                             disabled={loadingLeak}
//                             className="text-accent hover:text-cyan-400 font-medium text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
//                           >
//                             {loadingLeak ? '로딩 중...' : '상세보기'}
//                           </button>
//                         </td>
//                       </tr>
//                     );
//                   })
//                 )}
//               </tbody>
//             </table>
//           </div>
//         </div>
//       )}
//
//       {/* Empty State */}
//       {!hasSearched && !isSearching && (
//         <div className="bg-dark-card rounded-lg shadow-lg border border-gray-700 p-12 text-center">
//           <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
//             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
//           </svg>
//           <h3 className="text-xl font-semibold text-gray-400 mb-2">검색을 시작하세요</h3>
//           <p className="text-gray-500">이메일, 전화번호, 사용자명 등을 입력하여 유출 여부를 확인하세요</p>
//         </div>
//       )}
//
//       {/* Detail Modal */}
//       {selectedLeak && (
//         <LeakDetailModal
//           leak={selectedLeak}
//           onClose={() => setSelectedLeak(null)}
//         />
//       )}
//     </div>
//   );
// };
//
// export default PersonalInfoLeak;

import React, { useState } from 'react';
// import Header from '../components/Header'; // 상단바 중복 방지를 위해 주석 처리
import axios from 'axios';
import LeakDetailModal from '../components/LeakDetailModal';
import Spinner from '../components/Spinner';

const PersonalInfoLeak = () => {
  // 입력 상태 분리 (이메일, 프로젝트 키워드)
  const [email, setEmail] = useState('');
  const [projectKeyword, setProjectKeyword] = useState('');

  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedLeak, setSelectedLeak] = useState(null);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!email) {
        alert("이메일 주소는 필수 입력 사항입니다.");
        return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      // 백엔드로 이메일과 프로젝트 키워드 둘 다 전송
      const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/search/personal-info`, {
        params: {
            query: email,
            project_keyword: projectKeyword
        }
      });

      if (response.data && response.data.elasticsearch_results) {
        setResults(response.data.elasticsearch_results);
      } else {
        setResults([]);
      }
    } catch (err) {
      console.error("Search error:", err);
      setError("검색 중 오류가 발생했거나, 결과가 없습니다.");
    } finally {
      setLoading(false);
    }
  };

  const openModal = (leakData) => {
    setSelectedLeak(leakData);
  };

  const closeModal = () => {
    setSelectedLeak(null);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white font-sans">
      <main className="container mx-auto px-6 py-12">
        <div className="mb-12">
          <h1 className="text-4xl font-bold mb-4">개인정보 유출 검색</h1>
          <p className="text-gray-400 text-lg">
            기업 이메일과 프로젝트명을 입력하여 딥웹/다크웹 유출 여부를 정밀 진단합니다.
          </p>
        </div>

        {/* 검색창 (2단 분리) */}
        <form onSubmit={handleSearch} className="bg-gray-800 p-8 rounded-xl shadow-lg border border-gray-700 mb-10">
          <div className="flex flex-col gap-4">
            {/* 첫째줄: 이메일 */}
            <div className="flex flex-col">
                <label className="text-gray-400 mb-2 font-medium ml-1">대상 이메일 주소 <span className="text-red-500">*</span></label>
                <input
                type="text"
                placeholder="예: test@samsung.com"
                className="bg-gray-900 border border-gray-600 rounded-lg px-6 py-4 text-white focus:outline-none focus:border-cyan-500 transition-colors text-lg"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                />
            </div>

            {/* 둘째줄: 프로젝트 키워드 + 버튼 */}
            <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1 flex flex-col">
                    <label className="text-gray-400 mb-2 font-medium ml-1">프로젝트 키워드 (선택)</label>
                    <input
                    type="text"
                    placeholder="예: Galaxy S25, Project Titan (내부 프로젝트명)"
                    className="bg-gray-900 border border-gray-600 rounded-lg px-6 py-4 text-white focus:outline-none focus:border-cyan-500 transition-colors text-lg"
                    value={projectKeyword}
                    onChange={(e) => setProjectKeyword(e.target.value)}
                    />
                </div>
                <div className="flex items-end">
                    <button
                    type="submit"
                    disabled={loading}
                    className="w-full md:w-auto bg-cyan-500 hover:bg-cyan-600 text-gray-900 font-bold px-10 py-4 rounded-lg transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed text-lg h-[62px]"
                    >
                    {loading ? '검색 중...' : '정밀 검색'}
                    </button>
                </div>
            </div>
          </div>
        </form>

        {/* 결과 영역 */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-20">
            <Spinner />
            <p className="text-gray-400 mt-4 animate-pulse">외부 위협 인텔리전스 수집 중... (최대 30초 소요)</p>
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500 text-red-500 p-6 rounded-xl mb-8 text-center flex flex-col items-center">
             <svg className="w-10 h-10 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
             <span className="font-bold">시스템 오류 발생</span>
             <span className="text-sm mt-1">{error}</span>
          </div>
        )}

        {!loading && !error && results.length > 0 && (
          <div className="bg-gray-800 rounded-xl shadow-lg border border-gray-700 overflow-hidden">
             {/* ... (기존 테이블 코드 그대로 유지) ... */}
             <div className="p-6 border-b border-gray-700 flex justify-between items-center bg-gray-800/50">
              <h2 className="text-xl font-bold text-white">검색 결과</h2>
              <span className="text-gray-400">총 {results.filter(item => item.data && item.data.original_link).length}개의 유효 결과</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-gray-700/50 text-gray-300">
                    <th className="p-5 font-semibold border-b border-gray-600 w-2/12">위험 유형</th>
                    <th className="p-5 font-semibold border-b border-gray-600 w-2/12">발견 키워드</th>
                    <th className="p-5 font-semibold border-b border-gray-600 w-3/12">출처</th>
                    <th className="p-5 font-semibold border-b border-gray-600 w-3/12">원본 링크</th>
                    <th className="p-5 font-semibold border-b border-gray-600 w-1/12 text-center">유출 시점</th>
                    <th className="p-5 font-semibold border-b border-gray-600 w-1/12 text-center">상세</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((item, index) => {
                    const data = item.data || {};

                    if (!data.id || !data.original_link || data.original_link === '링크 없음') {
                        return null;
                    }

                    return (
                      <tr key={index} className="border-b border-gray-700 hover:bg-gray-700/30 transition-colors">
                        <td className="p-5">
                          <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                            data.keyword_type === 'credential' ? 'bg-red-500/20 text-red-400' :
                            data.keyword_type === 'asset' ? 'bg-yellow-500/20 text-yellow-400' :
                            data.keyword_type === 'project' ? 'bg-purple-500/20 text-purple-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>
                            {data.keyword_type ? data.keyword_type.toUpperCase() : 'UNKNOWN'}
                          </span>
                        </td>
                        <td className="p-5">
                            <span className={`font-medium px-2 py-1 rounded text-sm ${
                                data.found_keyword && data.found_keyword !== data.target_email
                                ? "bg-red-600/30 text-red-200 border border-red-500/50 animate-pulse"
                                : "text-gray-300 bg-gray-700"
                            }`}>
                                {data.found_keyword || data.target_email || '-'}
                            </span>
                        </td>
                        <td className="p-5 text-gray-300 text-sm">
                          {data.source || data.source_id || 'Unknown Source'}
                        </td>
                        <td className="p-5">
                          {data.original_link && String(data.original_link).startsWith('http') ? (
                            <a href={data.original_link} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300 underline truncate block max-w-xs text-sm">
                              {data.original_link}
                            </a>
                          ) : (
                            <span className="text-gray-500 text-sm">-</span>
                          )}
                        </td>
                        <td className="p-5 text-center text-gray-400 text-sm">
                          {data.leak_date ? String(data.leak_date).substring(0, 10) : '-'}
                        </td>
                        <td className="p-5 text-center">
                          <button onClick={() => openModal(data)} className="text-cyan-400 hover:text-white font-medium text-sm border border-cyan-500/30 hover:bg-cyan-500 hover:border-transparent px-4 py-2 rounded transition-all">
                            보기
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {!loading && !error && email && results.length === 0 && (
          <div className="text-center py-16 bg-green-500/10 rounded-xl border border-green-500/30">
            <svg className="w-16 h-16 text-green-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            <h3 className="text-2xl font-bold text-green-400 mb-2">유출 내역이 발견되지 않았습니다</h3>
            <p className="text-gray-400 text-lg">입력하신 이메일은 현재 알려진 위협에서 안전합니다.</p>
          </div>
        )}
      </main>

      {/* 상세 보기 모달 */}
      {selectedLeak && (
        <LeakDetailModal
          isOpen={!!selectedLeak}
          onClose={closeModal}
          leak={selectedLeak}
        />
      )}
    </div>
  );
};

export default PersonalInfoLeak;