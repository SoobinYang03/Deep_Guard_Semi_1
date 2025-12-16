import React from 'react';

const BarChart = ({ data }) => {
  const maxLeaks = Math.max(...data.map(d => d.leaks));

  return (
    <div className="h-80 flex items-end justify-around border-b border-gray-700 relative pb-8 pt-10">
      {data.map((item, index) => {
        const heightPercentage = (item.leaks / maxLeaks) * 70;
        const barColor = item.leaks > 2000 ? 'bg-danger' : 'bg-accent';
        const textColor = item.leaks > 2000 ? 'text-danger' : 'text-gray-400';
        
        return (
          <div
            key={index}
            className="flex flex-col items-center h-full justify-end relative"
            title={`${item.month}: ${item.leaks}건`}
          >
            <div className={`mb-1 text-xs font-medium ${textColor}`}>{item.leaks}</div>
            <div
              className={`w-10 ${barColor} rounded-t-md transition-all duration-500 shadow-lg`}
              style={{ height: `${heightPercentage}%`, minHeight: '10px' }}
            ></div>
            <span className="absolute -bottom-7 text-sm text-gray-300 font-medium whitespace-nowrap">{item.month}</span>
          </div>
        );
      })}
    </div>
  );
};

export default BarChart;
