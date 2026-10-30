import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopNav from './TopNav';

export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-background relative cyber-grid-bg text-slate-100 flex flex-col">
      {/* Subtle top ambient radial lighting */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-cyan-500/5 blur-[120px] pointer-events-none -z-10" />

      {/* Sidebar navigation */}
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />

      {/* Main content wrapper */}
      <div className="flex-1 flex flex-col">
        <TopNav collapsed={collapsed} />

        <main
          className={`flex-1 transition-all duration-300 p-4 sm:p-6 lg:p-8 max-w-[1600px] ${
            collapsed ? 'ml-20' : 'ml-64'
          }`}
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}

