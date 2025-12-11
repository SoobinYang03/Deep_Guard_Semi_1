import React, { useState, useEffect } from 'react';
import { uploadLeakFile, getSources } from '../services/api';
import Spinner from './Spinner';
import SuccessModal from './SuccessModal';

function UploadLeakModal({ isOpen, onClose, onUploadSuccess }) {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  
  const [formData, setFormData] = useState({
    source_id: '',
    source_name: '',
    source_type: 'darkweb',
    source_description: '',
    original_link: '',
    leak_description: '',
    leak_date: new Date().toISOString().split('T')[0],
    severity: 'medium',
    file: null,
    file_name: ''
  });

  useEffect(() => {
    if (isOpen) {
      fetchSources();
    }
  }, [isOpen]);

  const fetchSources = async () => {
    try {
      const response = await getSources();
      console.log('Sources response:', response);
      setSources(response.data?.sources || response.sources || []);
    } catch (error) {
      console.error('출처 목록 로드 실패:', error);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setFormData(prev => ({
        ...prev,
        file: file,
        file_name: file.name
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.file) {
      setUploadStatus({ type: 'error', message: '파일을 선택해주세요.' });
      return;
    }

    if (!formData.source_id && (!formData.source_name || !formData.source_type)) {
      setUploadStatus({ type: 'error', message: '출처를 선택하거나 새로운 출처 정보를 입력해주세요.' });
      return;
    }

    setLoading(true);
    setUploadStatus(null);

    try {
      const data = new FormData();
      data.append('file', formData.file);
      
      if (formData.source_id) {
        data.append('source_id', formData.source_id);
      } else {
        data.append('source_name', formData.source_name);
        data.append('source_type', formData.source_type);
        if (formData.source_description) {
          data.append('source_description', formData.source_description);
        }
      }
      
      data.append('original_link', formData.original_link);
      data.append('leak_description', formData.leak_description);
      data.append('leak_date', formData.leak_date);
      data.append('severity', formData.severity);
      data.append('file_name', formData.file_name);

      const response = await uploadLeakFile(data);
      
      setUploadResult(response);
      setShowSuccessModal(true);
      
      // 폼 초기화
      setFormData({
        source_id: '',
        source_name: '',
        source_type: 'darkweb',
        source_description: '',
        original_link: '',
        leak_description: '',
        leak_date: new Date().toISOString().split('T')[0],
        severity: 'medium',
        file: null,
        file_name: ''
      });
      
      // 파일 input 초기화
      const fileInput = document.getElementById('upload-file-input');
      if (fileInput) fileInput.value = '';
      
    } catch (error) {
      setUploadStatus({
        type: 'error',
        message: error.response?.data?.detail || '업로드 중 오류가 발생했습니다.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSuccessModalClose = () => {
    setShowSuccessModal(false);
    onClose();
    if (onUploadSuccess) {
      onUploadSuccess();
    }
  };

  const handleModalClose = () => {
    setFormData({
      source_id: '',
      source_name: '',
      source_type: 'darkweb',
      source_description: '',
      original_link: '',
      leak_description: '',
      leak_date: new Date().toISOString().split('T')[0],
      severity: 'medium',
      file: null,
      file_name: ''
    });
    setUploadStatus(null);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-40 overflow-y-auto">
        <div className="bg-dark-card rounded-lg shadow-xl max-w-3xl w-full mx-4 my-8 border border-gray-700">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-700">
            <div>
              <h2 className="text-2xl font-bold text-white">유출 파일 업로드</h2>
              <p className="mt-1 text-sm text-gray-400">
                새로운 유출 파일을 업로드하고 Elasticsearch에 인덱싱합니다.
              </p>
            </div>
            <button
              onClick={handleModalClose}
              className="text-gray-400 hover:text-white transition"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </button>
          </div>

          {/* Body */}
          <div className="p-6 max-h-[70vh] overflow-y-auto">
            {uploadStatus && (
              <div className={`p-4 rounded-lg mb-6 ${
                uploadStatus.type === 'success' 
                  ? 'bg-green-900/30 border border-green-500 text-green-400' 
                  : 'bg-red-900/30 border border-red-500 text-red-400'
              }`}>
                {uploadStatus.message}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* 출처 선택 섹션 */}
              <div className="border-b border-gray-700 pb-6">
                <h3 className="text-lg font-semibold text-white mb-4">출처 정보</h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      기존 출처 선택
                    </label>
                    <select
                      name="source_id"
                      value={formData.source_id}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                    >
                      <option value="">새로운 출처 등록</option>
                      {sources.map(source => (
                        <option key={source._id} value={source._id}>
                          {source.name} ({source.type})
                        </option>
                      ))}
                    </select>
                  </div>

                  {!formData.source_id && (
                    <>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">
                            출처 이름 <span className="text-red-400">*</span>
                          </label>
                          <input
                            type="text"
                            name="source_name"
                            value={formData.source_name}
                            onChange={handleInputChange}
                            className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                            placeholder="예: RaidForums"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">
                            출처 유형 <span className="text-red-400">*</span>
                          </label>
                          <select
                            name="source_type"
                            value={formData.source_type}
                            onChange={handleInputChange}
                            className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                          >
                            <option value="darkweb">다크웹</option>
                            <option value="telegram">텔레그램</option>
                            <option value="surfaceweb">표면웹</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                          출처 설명
                        </label>
                        <textarea
                          name="source_description"
                          value={formData.source_description}
                          onChange={handleInputChange}
                          rows={2}
                          className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                          placeholder="출처에 대한 설명을 입력하세요"
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* 유출 정보 섹션 */}
              <div className="border-b border-gray-700 pb-6">
                <h3 className="text-lg font-semibold text-white mb-4">유출 정보</h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      원본 링크
                    </label>
                    <input
                      type="url"
                      name="original_link"
                      value={formData.original_link}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                      placeholder="https://example.com/thread/12345"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      유출 설명 <span className="text-red-400">*</span>
                    </label>
                    <textarea
                      name="leak_description"
                      value={formData.leak_description}
                      onChange={handleInputChange}
                      rows={3}
                      className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                      placeholder="유출 내용에 대한 설명을 입력하세요"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        유출 날짜 <span className="text-red-400">*</span>
                      </label>
                      <input
                        type="date"
                        name="leak_date"
                        value={formData.leak_date}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        심각도 <span className="text-red-400">*</span>
                      </label>
                      <select
                        name="severity"
                        value={formData.severity}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                      >
                        <option value="low">낮음</option>
                        <option value="medium">보통</option>
                        <option value="high">높음</option>
                        <option value="critical">심각</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              {/* 파일 업로드 섹션 */}
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">파일 업로드</h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      파일 선택 <span className="text-red-400">*</span>
                    </label>
                    <input
                      id="upload-file-input"
                      type="file"
                      accept=".csv,.tsv,.json,.ndjson"
                      onChange={handleFileChange}
                      className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-accent file:text-dark-bg hover:file:bg-cyan-600"
                      required
                    />
                    <p className="mt-1 text-xs text-gray-400">
                      지원 형식: CSV, TSV, JSON, NDJSON
                    </p>
                  </div>

                  {formData.file && (
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2">
                        파일 이름
                      </label>
                      <input
                        type="text"
                        name="file_name"
                        value={formData.file_name}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-accent focus:border-accent"
                      />
                      <p className="mt-1 text-xs text-gray-400">
                        Elasticsearch 인덱스 이름은 자동으로 생성됩니다
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* 제출 버튼 */}
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={handleModalClose}
                  className="px-6 py-2 bg-gray-600 text-white font-semibold rounded-md hover:bg-gray-700 transition duration-150"
                >
                  취소
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2 bg-accent text-dark-bg font-semibold rounded-md hover:bg-cyan-600 focus:outline-none focus:ring-2 focus:ring-accent disabled:bg-gray-600 disabled:cursor-not-allowed flex items-center transition duration-150"
                >
                  {loading ? (
                    <>
                      <Spinner />
                      <span className="ml-2">업로드 중...</span>
                    </>
                  ) : (
                    '업로드'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>

      {/* 성공 모달 */}
      <SuccessModal
        isOpen={showSuccessModal}
        onClose={handleSuccessModalClose}
        title="업로드 완료"
        message="유출 파일이 성공적으로 업로드되고 인덱싱되었습니다."
        details={uploadResult ? [
          { label: '인덱스 이름', value: uploadResult.index_name },
          { label: '업로드된 레코드', value: `${uploadResult.total_records}건` },
          { label: '성공', value: `${uploadResult.success}건` },
          { label: '실패', value: `${uploadResult.failed}건` }
        ] : []}
      />
    </>
  );
}

export default UploadLeakModal;
