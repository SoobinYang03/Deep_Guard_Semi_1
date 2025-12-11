import React, { useState, useEffect } from 'react';
import { updateLeakStatus } from '../services/api';

const LeakDetailModal = ({ leak, onClose, onStatusUpdate }) => {
  const [status, setStatus] = useState(leak?.status || 'new');
  const [updating, setUpdating] = useState(false);
  
  // leak가 변경될 때마다 status 업데이트
  useEffect(() => {
    if (leak?.status) {
      setStatus(leak.status);
    }
  }, [leak]);
  
  if (!leak) return null;

  const getSeverityColor = (severity) => {
    const sev = severity?.toLowerCase();
    switch(sev) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-green-500';
      default: return 'text-gray-500';
    }
  };

  const getSeverityLabel = (severity) => {
    const labels = {
      'critical': 'Critical',
      'high': 'High',
      'medium': 'Medium',
      'low': 'Low'
    };
    return labels[severity?.toLowerCase()] || severity || 'N/A';
  };
  
  const getSourceTypeLabel = (type) => {
    const labels = {
      'darkweb': '다크웹',
      'surfaceweb': '표면 웹',
      'telegram': '텔레그램'
    };
    return labels[type?.toLowerCase()] || type || 'N/A';
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

  const getStatusLabel = (status) => {
    const labels = {
      'new': '신규',
      'processing': '처리중',
      'investigating': '조사중',
      'resolved': '해결됨'
    };
    return labels[status] || '신규';
  };

  const getStatusColor = (status) => {
    const colors = {
      'new': 'bg-red-900/40 text-red-400 border-red-700/50',
      'processing': 'bg-yellow-900/40 text-yellow-400 border-yellow-700/50',
      'investigating': 'bg-blue-900/40 text-blue-400 border-blue-700/50',
      'resolved': 'bg-green-900/40 text-green-400 border-green-700/50'
    };
    return colors[status] || colors['new'];
  };

  const handleStatusChange = async (newStatus) => {
    if (!leak._id || updating) return;
    
    setUpdating(true);
    try {
      await updateLeakStatus(leak._id, newStatus);
      setStatus(newStatus);
      if (onStatusUpdate) {
        onStatusUpdate();
      }
    } catch (error) {
      console.error('Status update failed:', error);
      alert('상태 변경에 실패했습니다.');
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div 
        className="bg-dark-card rounded-lg shadow-2xl border border-gray-700 max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-dark-card border-b border-gray-700 p-6 flex items-start justify-between">
          <h2 className="text-2xl font-bold text-white">유출 내용</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition p-2 hover:bg-gray-700 rounded-lg"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>

        <div className="p-6">
          {/* 기본 정보 그리드 */}
          <div className="grid grid-cols-2 gap-6 mb-6">
            <div>
              <div className="text-gray-400 text-sm mb-2">소스:</div>
              <div className="text-white font-medium">
                {leak.original_link || 'N/A'}
              </div>
            </div>

            <div>
              <div className="text-gray-400 text-sm mb-2">유출 경로:</div>
              <div className="text-white font-medium">
                {leak.source ? getSourceTypeLabel(leak.source.type) : 'N/A'}
              </div>
            </div>

            <div>
              <div className="text-gray-400 text-sm mb-2">위험 수준:</div>
              <div className={`font-semibold ${getSeverityColor(leak.severity)}`}>
                {getSeverityLabel(leak.severity)}
              </div>
            </div>

            <div>
              <div className="text-gray-400 text-sm mb-2">탐지 건수:</div>
              <div className="text-white font-medium">
                {leak.files ? leak.files.reduce((sum, f) => sum + (f.record_count || 0), 0).toLocaleString() : 0}
              </div>
            </div>

            <div className="col-span-2">
              <div className="text-gray-400 text-sm mb-2">대응 상태:</div>
              <select 
                value={status}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={updating}
                className={`w-full px-4 py-2 border rounded-md font-medium focus:outline-none transition ${getStatusColor(status)} ${updating ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                <option value="new">신규</option>
                <option value="processing">처리중</option>
                <option value="investigating">조사중</option>
                <option value="resolved">해결됨</option>
                <option>완료</option>
              </select>
            </div>
          </div>

          {/* 관련 정보 섹션 */}
          <div className="border-t border-gray-700 pt-6">
            <h3 className="text-lg font-semibold text-white mb-4">관련 정보</h3>
            
            <div className="space-y-3">
              {leak.files && leak.files.length > 0 ? (
                leak.files.map((file, idx) => (
                  <div key={idx}>
                    <div className="text-gray-400 text-sm mb-2">
                      • 코드 유형: {file.file_name || 'Unknown'}
                    </div>
                    {file.columns && file.columns.length > 0 && (
                      <div className="text-gray-400 text-sm mb-2">
                        • 탐지 일시: {formatDate(file.uploaded_at)}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <>
                  <div className="text-gray-400 text-sm">• 코드 유형: Backend API, Database Schema, Configuration Files</div>
                  <div className="text-gray-400 text-sm">• 탐지 일시: {formatDate(leak.leak_date)}</div>
                </>
              )}
              
              <div className="text-gray-400 text-sm">
                • 유출 추정 일시: {formatDate(leak.leak_date)} ~ {formatDate(leak.updated_at || leak.created_at)}
              </div>
              
              {leak.files && leak.files.length > 0 && leak.files.some(f => f.columns?.length > 0) && (
                <div className="text-gray-400 text-sm">
                  • 포함된 민감 정보: API 키, 데이터베이스 자격 증명, 서버 설정
                </div>
              )}
              
              <div className="text-gray-400 text-sm">• 영향 범위: 전체 시스템 보안 위협</div>
              <div className="text-gray-400 text-sm">• 권장 조치: 모든 API 키 및 자격 증명 즉시 변경, 접근 로그 분석</div>
            </div>
          </div>

          {/* 유출된 칼럼 섹션 */}
          {leak.files && leak.files.some(f => f.columns?.length > 0) && (
            <div className="border-t border-gray-700 pt-6 mt-6">
              <h3 className="text-lg font-semibold text-white mb-4">유출된 데이터 필드</h3>
              
              {leak.files.map((file, idx) => (
                file.columns && file.columns.length > 0 && (
                  <div key={idx} className="mb-4">
                    <div className="text-sm font-medium text-gray-300 mb-2">
                      {file.file_name} ({file.columns.length}개 필드)
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {file.columns.map((col, colIdx) => (
                        <span 
                          key={colIdx} 
                          className="px-3 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded-md text-xs font-medium"
                          title={`타입: ${col.type}`}
                        >
                          {col.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              ))}
            </div>
          )}

          {/* 설명 섹션 */}
          {leak.description && (
            <div className="border-t border-gray-700 pt-6 mt-6">
              <h3 className="text-lg font-semibold text-white mb-4">상세 설명</h3>
              <div className="bg-gray-800/50 rounded-lg p-4">
                <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{leak.description}</p>
              </div>
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-dark-card border-t border-gray-700 p-6 flex justify-end space-x-3">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-lg transition"
          >
            닫기
          </button>
          <button
            className="px-5 py-2 bg-accent hover:bg-cyan-600 text-dark-bg font-semibold rounded-lg transition"
          >
            보고서 다운로드
          </button>
        </div>
      </div>
    </div>
  );
};

export default LeakDetailModal;
