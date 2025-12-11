import React from 'react';

const InfoCard = ({ title, value, subtitle, color = 'accent', icon }) => {
  const colorClasses = {
    danger: 'border-danger text-danger',
    caution: 'border-caution text-caution',
    accent: 'border-accent text-accent',
    safe: 'border-safe text-safe'
  };

  return (
    <div className={`bg-dark-card p-6 rounded-xl shadow-2xl border-l-4 ${colorClasses[color].split(' ')[0]}`}>
      <p className="text-sm text-gray-400 font-medium">{title}</p>
      <p className={`text-3xl font-extrabold mt-1 ${colorClasses[color].split(' ')[1]}`}>
        {value}
      </p>
      {subtitle && (
        <p className="text-xs text-gray-500 mt-2">{subtitle}</p>
      )}
    </div>
  );
};

export default InfoCard;
