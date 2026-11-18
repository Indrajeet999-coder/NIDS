import React, { useEffect, useState } from 'react';
import { getHealth, getMetrics, getDashboardTelemetry } from './api';
import Sidebar from './components/Sidebar';
import TopHeader from './components/TopHeader';
import OverviewView from './components/OverviewView';
import TrafficAnalysisView from './components/TrafficAnalysisView';
import FlowSimulatorView from './components/FlowSimulatorView';
import CsvAnalyzerView from './components/CsvAnalyzerView';
import ModelAnalyticsView from './components/ModelAnalyticsView';
import DetectionHistoryView from './components/DetectionHistoryView';
import AlertToast from './components/AlertToast';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [activeDataset, setActiveDataset] = useState('5_mixed_enterprise_soc.csv');
  const [telemetryData, setTelemetryData] = useState(null);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [metricsData, setMetricsData] = useState(null);
  const [toasts, setToasts] = useState([]);

  const notify = (type, message, details = null) => {
    const id = Date.now() + Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, type, message, details }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4500);
  };

  const dismissToast = (id) => setToasts((prev) => prev.filter((t) => t.id !== id));

  const checkHealthStatus = async (showNotification = false) => {
    setHealthLoading(true);
    try {
      const data = await getHealth();
      setHealth(data);
      if (data?.active_dataset) {
        setActiveDataset(data.active_dataset);
      }
      if (showNotification) {
        notify('success', 'Backend API Online', `Connected to ${data.model_name}`);
      }
    } catch {
      setHealth({ status: 'offline', model_name: 'XGBoost (Offline)', expected_feature_count: 25 });
      if (showNotification) {
        notify('warning', 'Backend Offline', 'Start with: uvicorn backend.main:app --reload');
      }
    } finally {
      setHealthLoading(false);
    }
  };

  const loadMetricsData = async () => {
    try {
      const data = await getMetrics();
      setMetricsData(data);
    } catch {
      // Fallback data used inside ModelAnalyticsView
    }
  };

  const loadTelemetry = async () => {
    setTelemetryLoading(true);
    try {
      const data = await getDashboardTelemetry();
      setTelemetryData(data);
      if (data?.active_dataset) {
        setActiveDataset(data.active_dataset);
      }
    } catch {
      // Views fallback to default mock/telemetry data if API unavailable
    } finally {
      setTelemetryLoading(false);
    }
  };

  useEffect(() => {
    checkHealthStatus(false);
    loadMetricsData();
    loadTelemetry();
  }, []);

  useEffect(() => {
    if (activeTab === 'overview' || activeTab === 'traffic') {
      loadTelemetry();
    }
  }, [activeTab]);

  const isHealthy = health && health.status === 'healthy';

  const renderView = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <OverviewView
            onNotify={notify}
            setActiveTab={setActiveTab}
            telemetryData={telemetryData}
          />
        );
      case 'traffic':
        return (
          <TrafficAnalysisView
            onNotify={notify}
            telemetryData={telemetryData}
          />
        );
      case 'simulator':
        return (
          <FlowSimulatorView
            onNotify={notify}
            onTelemetryUpdated={loadTelemetry}
          />
        );
      case 'csv':
        return (
          <CsvAnalyzerView
            onNotify={notify}
            onTelemetryUpdated={loadTelemetry}
          />
        );
      case 'model':
        return <ModelAnalyticsView metricsData={metricsData} onNotify={notify} />;
      case 'history':
        return <DetectionHistoryView onNotify={notify} />;
      default:
        return (
          <OverviewView
            onNotify={notify}
            setActiveTab={setActiveTab}
            telemetryData={telemetryData}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#060d1f] text-gray-100 flex">
      {/* Fixed Left Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} isHealthy={isHealthy} />

      {/* Main Content (offset by sidebar width) */}
      <div className="flex-1 ml-56 flex flex-col min-h-screen">
        <TopHeader
          health={health}
          healthLoading={healthLoading}
          activeDataset={activeDataset}
          onRefreshHealth={() => {
            checkHealthStatus(true);
            loadTelemetry();
          }}
        />
        <main className="flex-1 p-6 overflow-auto">
          <div className="animate-fade-in" key={activeTab}>
            {renderView()}
          </div>
        </main>
      </div>

      {/* Alert Toasts */}
      <AlertToast toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
