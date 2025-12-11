import React from 'react';

const Spinner = ({ size = 'w-4 h-4' }) => {
  return (
    <div className={`spinner border-2 border-gray-700 rounded-full ${size} animate-spin`}
         style={{
           borderTopColor: '#06B6D4',
           borderLeftColor: '#06B6D4',
         }}
    ></div>
  );
};

export default Spinner;
