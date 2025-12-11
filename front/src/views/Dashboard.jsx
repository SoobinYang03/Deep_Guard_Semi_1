import React from 'react';
import InfoCard from '../components/InfoCard';
import BarChart from '../components/BarChart';

const Dashboard = () => {
  const mockChartData = [
    { month: '1월', leaks: 1200 },
    { month: '2월', leaks: 800 },
    { month: '3월', leaks: 2500 },
    { month: '4월', leaks: 1500 },
    { month: '5월', leaks: 1000 },
    { month: '6월', leaks: 500 },
    { month: '7월', leaks: 1800 },
    { month: '8월', leaks: 1900 },
    { month: '9월', leaks: 3000 },
    { month: '10월', leaks: 2000 },
    { month: '11월', leaks: 1300 },
    { month: '12월', leaks: 900 }
  ];

  return (
    <section>
      <h1 className="text-3xl font-bold mb-6 text-white">Overview</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-4 gap-6">
        <InfoCard 
          title="총 유출 건수 (금월)"
          value="3,000"
          subtitle="지난달 대비 58% 증가"
          color="danger"
        />
        <InfoCard 
          title="관리자 유출 계정"
          value="4"
          subtitle="즉각적인 비밀번호 변경 필요"
          color="caution"
        />
        <InfoCard 
          title="신규 OSINT 수집 건"
          value="72"
          subtitle="오늘 새벽 갱신 완료"
          color="accent"
        />
        <div className="hidden xl:block bg-dark-card p-6 rounded-xl shadow-2xl border-l-4 border-gray-600/50">
          <p className="text-sm text-gray-400 font-medium">DeepGuard 상태</p>
          <p className="text-3xl font-extrabold mt-1 text-safe">Online</p>
          <p className="text-xs text-gray-500 mt-2">모든 모듈 정상 작동 중</p>
        </div>
      </div>

      {/* Chart and Quick Action Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8">
        {/* Chart */}
        <div className="bg-dark-card p-6 rounded-xl shadow-2xl lg:col-span-2">
          <h2 className="text-xl font-semibold mb-6">주간 유출 증감 추이 분석</h2>
          <BarChart data={mockChartData} />
          <div className="flex justify-end mt-4">
            <span className="text-xs text-danger">9월 피크 발생: 평균 대비 2.3배</span>
          </div>
        </div>

        {/* Quick Action Panel */}
        <div className="bg-dark-card p-6 rounded-xl shadow-2xl space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-semibold mb-4">신속 대응 모듈</h2>
            <p className="text-sm text-gray-400 mb-4">현재 위협 상황에 기반한 우선순위 대응 액션.</p>
            <ul className="space-y-3">
              <li className="flex items-center space-x-3 text-sm p-3 bg-dark-bg rounded-lg border border-danger/50">
                <span className="text-danger font-bold">1순위</span> 
                <span className="text-gray-300">ADMIN 계정 비밀번호 전면 교체</span>
              </li>
              <li className="flex items-center space-x-3 text-sm p-3 bg-dark-bg rounded-lg border border-caution/50">
                <span className="text-caution font-bold">2순위</span> 
                <span className="text-gray-300">위험 URL 목록에 대한 접근 차단</span>
              </li>
              <li className="flex items-center space-x-3 text-sm p-3 bg-dark-bg rounded-lg border border-accent/50">
                <span className="text-accent font-bold">3순위</span> 
                <span className="text-gray-300">OSINT 정보 기반 위협 요소 검증</span>
              </li>
            </ul>
          </div>
          <button className="w-full py-3 bg-accent hover:bg-cyan-600 text-dark-bg font-bold rounded-lg transition duration-150">
            전체 대응 매뉴얼 보기
          </button>
        </div>
      </div>
    </section>
  );
};

export default Dashboard;
