import { useState, useEffect } from 'react';

interface HealthStatus {
  status: string;
  timestamp: string;
  version: string;
  uptime: number;
  database: {
    status: string;
    type: string;
  };
  generators: {
    total: number;
    categories: number;
  };
}

interface StatusDashboardProps {
  apiBaseUrl?: string;
}

export default function StatusDashboard({ apiBaseUrl = 'http://localhost:8001' }: StatusDashboardProps) {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchHealth = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/health`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setHealth(data);
      setLastUpdate(new Date());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch health status');
      console.error('Failed to fetch health:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getStatusColor = (status: string): string => {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'connected':
      case 'ok':
        return 'text-green';
      case 'degraded':
      case 'warning':
        return 'text-yellow';
      case 'unhealthy':
      case 'error':
      case 'disconnected':
        return 'text-red';
      default:
        return 'text-subtext1';
    }
  };

  const getStatusIcon = (status: string): string => {
    switch (status.toLowerCase()) {
      case 'healthy':
      case 'connected':
      case 'ok':
        return '●';
      case 'degraded':
      case 'warning':
        return '◐';
      case 'unhealthy':
      case 'error':
      case 'disconnected':
        return '●';
      default:
        return '○';
    }
  };

  if (loading) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-surface1">
        <div className="animate-pulse">
          <div className="h-6 bg-surface1 rounded w-1/3 mb-4"></div>
          <div className="grid grid-cols-2 gap-4">
            <div className="h-20 bg-surface1 rounded"></div>
            <div className="h-20 bg-surface1 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-red">
        <div className="flex items-center mb-4">
          <span className="text-red text-xl mr-2">●</span>
          <h3 className="text-lg font-semibold text-red">Backend Offline</h3>
        </div>
        <p className="text-subtext1 mb-4">{error}</p>
        <button 
          onClick={fetchHealth}
          className="px-4 py-2 bg-red text-base rounded-lg hover:bg-red/80 transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  if (!health) return null;

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-semibold text-text">System Status</h2>
        <div className="text-sm text-subtext1">
          Last updated: {lastUpdate.toLocaleTimeString()}
        </div>
      </div>

      {/* Overall Status */}
      <div className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <span className={`text-xl mr-3 ${getStatusColor(health.status)}`}>
              {getStatusIcon(health.status)}
            </span>
            <div>
              <h3 className="font-semibold text-text">Pulse API</h3>
              <p className="text-sm text-subtext1">Version {health.version}</p>
            </div>
          </div>
          <div className="text-right">
            <p className={`font-semibold ${getStatusColor(health.status)}`}>
              {health.status.toUpperCase()}
            </p>
            <p className="text-sm text-subtext1">
              Uptime: {formatUptime(health.uptime)}
            </p>
          </div>
        </div>
      </div>

      {/* Component Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Database Status */}
        <div className="p-4 bg-mantle rounded-lg border border-surface1">
          <div className="flex items-center mb-2">
            <span className={`text-lg mr-2 ${getStatusColor(health.database.status)}`}>
              {getStatusIcon(health.database.status)}
            </span>
            <h4 className="font-semibold text-text">Database</h4>
          </div>
          <p className="text-sm text-subtext1">{health.database.type}</p>
          <p className={`text-sm font-medium ${getStatusColor(health.database.status)}`}>
            {health.database.status}
          </p>
        </div>

        {/* Generators Status */}
        <div className="p-4 bg-mantle rounded-lg border border-surface1">
          <div className="flex items-center mb-2">
            <span className="text-lg mr-2 text-green">●</span>
            <h4 className="font-semibold text-text">Generators</h4>
          </div>
          <p className="text-sm text-subtext1">{health.generators.total} available</p>
          <p className="text-sm font-medium text-green">
            {health.generators.categories} categories
          </p>
        </div>

        {/* Frontend Status */}
        <div className="p-4 bg-mantle rounded-lg border border-surface1">
          <div className="flex items-center mb-2">
            <span className="text-lg mr-2 text-green">●</span>
            <h4 className="font-semibold text-text">Frontend</h4>
          </div>
          <p className="text-sm text-subtext1">Astro + React</p>
          <p className="text-sm font-medium text-green">Connected</p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="mt-6 flex gap-3">
        <button
          onClick={fetchHealth}
          className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 transition-colors"
        >
          Refresh Status
        </button>
        <a
          href={`${apiBaseUrl}/api/v1/docs`}
          target="_blank"
          rel="noopener noreferrer"
          className="px-4 py-2 bg-mauve text-base rounded-lg hover:bg-mauve/80 transition-colors"
        >
          API Docs
        </a>
      </div>
    </div>
  );
}