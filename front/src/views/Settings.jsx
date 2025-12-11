import React, { useState } from 'react';

const Settings = () => {
  const [emails, setEmails] = useState([
    'admin@deepguard.com',
    'user1@deepguard.com',
    'user2@deepguard.com'
  ]);
  const [newEmail, setNewEmail] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  const addEmail = () => {
    if (newEmail.trim() && !emails.includes(newEmail.trim())) {
      setEmails([...emails, newEmail.trim()]);
      setNewEmail('');
    }
  };

  const removeEmail = (emailToRemove) => {
    setEmails(emails.filter(email => email !== emailToRemove));
  };

  const filteredEmails = emails.filter(email =>
    email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white">설정</h1>
      
      <div className="bg-dark-card rounded-lg p-8 shadow-lg">
        <h2 className="text-xl font-semibold text-accent mb-6">모니터링 이메일 목록</h2>
        
        {/* Add Email Section */}
        <div className="mb-6">
          <div className="flex gap-3">
            <div className="flex gap-3 flex-1">
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addEmail()}
                placeholder="새 이메일 주소 입력"
                className="flex-1 px-4 py-2 bg-dark-bg border border-gray-600 rounded-md text-text-primary placeholder-gray-500 focus:outline-none focus:border-accent transition"
              />
              <button
                onClick={addEmail}
                className="px-6 py-2 bg-accent hover:bg-cyan-600 text-dark-bg font-semibold rounded-md transition duration-150 whitespace-nowrap"
              >
                추가
              </button>
            </div>

            <div className="flex gap-3 flex-1">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && {}}
                placeholder="이메일 검색..."
                className="flex-1 px-4 py-2 bg-dark-bg border border-gray-600 rounded-md text-text-primary placeholder-gray-500 focus:outline-none focus:border-accent transition"
              />
              <button
                onClick={() => {}}
                className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-text-primary font-semibold rounded-md transition duration-150 whitespace-nowrap"
              >
                검색
              </button>
            </div>
          </div>
        </div>

        {/* Emails List */}
        <div className="grid grid-cols-2 gap-3">
          {filteredEmails.length > 0 ? (
            filteredEmails.map((email, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-4 bg-dark-bg border border-gray-700 rounded-md hover:border-gray-600 transition"
              >
                <span className="text-text-primary">{email}</span>
                <button
                  onClick={() => removeEmail(email)}
                  className="w-6 h-6 flex items-center justify-center bg-red-600 hover:bg-red-700 text-white rounded-full transition duration-150 text-sm"
                >
                  ✕
                </button>
              </div>
            ))
          ) : (
            <p className="text-center text-gray-500 py-8 col-span-2">이메일이 없습니다.</p>
          )}
        </div>

        {/* Total Count */}
        <div className="mt-6 pt-4 border-t border-gray-700">
          <p className="text-sm text-gray-400">
            총 {emails.length}개의 이메일을 모니터링하고 있습니다.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Settings;
