import { useState, useEffect } from 'react';

interface Scenario {
  id: string;
  name: string;
  description: string;
  duration_days?: number;
  duration_minutes?: number;
  total_events: number;
  phases: string[];
}

interface Destination {
  id: string;
  name: string;
  type: 'hec' | 'syslog';
}

interface ScenarioConfig {
  scenario_id: string;
  destination_id: string;
  workers: number;
  tag_phase: boolean;
  tag_trace: boolean;
  trace_id: string;
  generate_noise: boolean;
  noise_events_count: number;
}

interface ScenarioOrchestratorProps {
  apiBaseUrl?: string;
}

export default function ScenarioOrchestrator({ apiBaseUrl = 'http://localhost:8001' }: ScenarioOrchestratorProps) {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [config, setConfig] = useState<ScenarioConfig>({
    scenario_id: '',
    destination_id: '',
    workers: 10,
    tag_phase: true,
    tag_trace: true,
    trace_id: '',
    generate_noise: false,
    noise_events_count: 1200
  });
  
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    Promise.all([fetchScenarios(), fetchDestinations()]);
  }, []);

  const fetchScenarios = async () => {
    try {
      // Mock scenarios data - in real implementation this would come from the API
      const mockScenarios: Scenario[] = [
        {
          id: 'attack_scenario_orchestrator',
          name: 'Operation Digital Heist',
          description: 'Sophisticated 14-day APT campaign against a financial services company. Simulates reconnaissance, initial access, persistence, privilege escalation, and data exfiltration.',
          duration_days: 14,
          total_events: 700,
          phases: ['Reconnaissance & Phishing', 'Initial Access', 'Persistence & Lateral Movement', 'Privilege Escalation', 'Data Exfiltration']
        },
        {
          id: 'enterprise_attack_scenario',
          name: 'Enterprise Breach Scenario',
          description: 'Enhanced enterprise attack scenario with 330+ events across multiple security products. Demonstrates correlated attack patterns.',
          duration_minutes: 60,
          total_events: 330,
          phases: ['Initial Compromise', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration', 'Persistence']
        },
        {
          id: 'finance_mfa_fatigue_scenario',
          name: 'Finance Employee MFA Fatigue Attack',
          description: 'Baseline (Days 1-7), MFA fatigue from Russia, OneDrive exfiltration, SOAR detections and automated response.',
          duration_days: 8,
          total_events: 135,
          phases: ['Normal Behavior', 'MFA Fatigue', 'Initial Access', 'Data Exfiltration', 'Detection & Response']
        },
        {
          id: 'insider_cloud_download_exfiltration',
          name: 'Insider Data Exfiltration via Cloud Download',
          description: 'Insider threat scenario: anomalous large-volume M365/SharePoint downloads (180+ files), DLP classification, and removable USB media copying.',
          duration_days: 8,
          total_events: 280,
          phases: ['Baseline', 'Off-Hours Access', 'Cloud Download Spike', 'USB Copy', 'Detection']
        },
        {
          id: 'showcase_attack_scenario',
          name: 'AI-SIEM Showcase Scenario',
          description: 'Showcase scenario demonstrating multi-platform correlation across EDR, Email, Identity, Cloud, Network, WAF, and more.',
          duration_minutes: 30,
          total_events: 200,
          phases: ['Phishing', 'Compromise', 'Movement', 'Privilege Escalation', 'Exfiltration']
        }
      ];
      
      setScenarios(mockScenarios);
    } catch (err) {
      setError('Failed to fetch scenarios');
    }
  };

  const fetchDestinations = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/destinations`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      setDestinations(data.destinations || []);
      setLoading(false);
    } catch (err) {
      setError('Failed to fetch destinations');
      setLoading(false);
    }
  };

  const runScenario = async () => {
    if (!config.scenario_id || !config.destination_id) {
      setError('Please select both scenario and destination');
      return;
    }

    setIsRunning(true);
    setProgress(['Initializing attack scenario...']);
    setError('');

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/scenarios/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Stream the scenario execution progress
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split('\n').filter(line => line.trim());
          
          for (const line of lines) {
            setProgress(prev => [...prev.slice(-30), line]); // Keep last 30 lines
          }
        }
      }

      setProgress(prev => [...prev, 'Attack scenario completed successfully!']);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Scenario execution failed';
      setError(errorMsg);
      setProgress(prev => [...prev, `ERROR: ${errorMsg}`]);
    } finally {
      setIsRunning(false);
    }
  };

  const stopScenario = () => {
    setIsRunning(false);
    setProgress(prev => [...prev, 'Scenario execution stopped by user']);
  };

  const clearProgress = () => {
    setProgress([]);
    setError('');
  };

  const generateTraceId = () => {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    setConfig({...config, trace_id: `pulse-${timestamp}-${random}`});
  };

  if (loading) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-surface1">
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-surface1 rounded w-1/3"></div>
          <div className="h-10 bg-surface1 rounded"></div>
          <div className="h-10 bg-surface1 rounded"></div>
        </div>
      </div>
    );
  }

  const selectedScenario = scenarios.find(s => s.id === config.scenario_id);
  const selectedDestination = destinations.find(d => d.id === config.destination_id);

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <h2 className="text-xl font-semibold text-text mb-6">Attack Scenario Orchestrator</h2>

      {error && (
        <div className="mb-4 p-4 bg-red/10 border border-red rounded-lg">
          <p className="text-red text-sm">{error}</p>
        </div>
      )}

      {/* Scenario Selection */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-subtext1 mb-2">
              Attack Scenario ({scenarios.length} available)
            </label>
            <select
              value={config.scenario_id}
              onChange={(e) => setConfig({...config, scenario_id: e.target.value})}
              disabled={isRunning}
              className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
            >
              <option value="">Select an attack scenario...</option>
              {scenarios.map(scenario => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-subtext1 mb-2">
              Destination ({destinations.filter(d => d.type === 'hec').length} HEC available)
            </label>
            <select
              value={config.destination_id}
              onChange={(e) => setConfig({...config, destination_id: e.target.value})}
              disabled={isRunning}
              className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
            >
              <option value="">Select a destination...</option>
              {destinations.filter(d => d.type === 'hec').map(dest => (
                <option key={dest.id} value={dest.id}>
                  {dest.name} (SDL HEC)
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">
                Parallel Workers
              </label>
              <input
                type="number"
                value={config.workers}
                onChange={(e) => setConfig({...config, workers: parseInt(e.target.value) || 1})}
                disabled={isRunning}
                min="1"
                max="50"
                className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">
                Noise Events
              </label>
              <input
                type="number"
                value={config.noise_events_count}
                onChange={(e) => setConfig({...config, noise_events_count: parseInt(e.target.value) || 0})}
                disabled={isRunning || !config.generate_noise}
                min="0"
                max="10000"
                className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center">
              <input
                type="checkbox"
                id="tag_phase"
                checked={config.tag_phase}
                onChange={(e) => setConfig({...config, tag_phase: e.target.checked})}
                disabled={isRunning}
                className="mr-2 rounded border-surface1 text-mauve focus:ring-mauve disabled:opacity-50"
              />
              <label htmlFor="tag_phase" className="text-sm text-subtext1">
                Tag events with scenario phase
              </label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                id="tag_trace"
                checked={config.tag_trace}
                onChange={(e) => setConfig({...config, tag_trace: e.target.checked})}
                disabled={isRunning}
                className="mr-2 rounded border-surface1 text-mauve focus:ring-mauve disabled:opacity-50"
              />
              <label htmlFor="tag_trace" className="text-sm text-subtext1">
                Tag events with trace ID
              </label>
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                id="generate_noise"
                checked={config.generate_noise}
                onChange={(e) => setConfig({...config, generate_noise: e.target.checked})}
                disabled={isRunning}
                className="mr-2 rounded border-surface1 text-mauve focus:ring-mauve disabled:opacity-50"
              />
              <label htmlFor="generate_noise" className="text-sm text-subtext1">
                Generate background noise data
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Trace ID Configuration */}
      {config.tag_trace && (
        <div className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
          <label className="block text-sm font-medium text-subtext1 mb-2">
            Trace ID (for correlation)
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={config.trace_id}
              onChange={(e) => setConfig({...config, trace_id: e.target.value})}
              disabled={isRunning}
              placeholder="Enter custom trace ID or generate one"
              className="flex-1 px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
            />
            <button
              onClick={generateTraceId}
              disabled={isRunning}
              className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 disabled:opacity-50 transition-colors"
            >
              Generate
            </button>
          </div>
        </div>
      )}

      {/* Selected Scenario Preview */}
      {selectedScenario && (
        <div className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
          <h3 className="font-semibold text-mauve mb-2">{selectedScenario.name}</h3>
          <p className="text-sm text-subtext1 mb-3">{selectedScenario.description}</p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-subtext1">Duration:</span>
              <p className="text-text font-medium">
                {selectedScenario.duration_days 
                  ? `${selectedScenario.duration_days} days`
                  : `${selectedScenario.duration_minutes} minutes`
                }
              </p>
            </div>
            <div>
              <span className="text-subtext1">Total Events:</span>
              <p className="text-text font-medium">{selectedScenario.total_events.toLocaleString()}</p>
            </div>
            <div>
              <span className="text-subtext1">Attack Phases:</span>
              <p className="text-text font-medium">{selectedScenario.phases.length} phases</p>
            </div>
          </div>

          <div className="mt-3">
            <span className="text-subtext1 text-sm">Phases:</span>
            <div className="flex flex-wrap gap-2 mt-1">
              {selectedScenario.phases.map((phase, index) => (
                <span 
                  key={index}
                  className="px-2 py-1 text-xs bg-surface0 text-subtext1 rounded border border-surface1"
                >
                  {index + 1}. {phase}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Control Buttons */}
      <div className="flex gap-3 mb-6">
        <button
          onClick={runScenario}
          disabled={isRunning || !config.scenario_id || !config.destination_id}
          className="px-6 py-2 bg-red text-base rounded-lg hover:bg-red/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isRunning ? 'Executing Attack...' : 'Launch Attack Scenario'}
        </button>
        
        {isRunning && (
          <button
            onClick={stopScenario}
            className="px-6 py-2 bg-yellow text-base rounded-lg hover:bg-yellow/80 transition-colors"
          >
            Stop Scenario
          </button>
        )}
        
        <button
          onClick={clearProgress}
          disabled={isRunning}
          className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 disabled:opacity-50 transition-colors"
        >
          Clear Log
        </button>
      </div>

      {/* Execution Progress */}
      {progress.length > 0 && (
        <div className="bg-mantle rounded-lg border border-surface1 p-4">
          <div className="flex justify-between items-center mb-3">
            <h3 className="font-semibold text-text">Attack Execution Log</h3>
            {isRunning && (
              <div className="flex items-center text-red">
                <div className="w-2 h-2 bg-red rounded-full animate-pulse mr-2"></div>
                <span className="text-sm">Executing</span>
              </div>
            )}
          </div>
          
          <div className="bg-surface0 rounded border border-surface1 p-3 max-h-80 overflow-y-auto">
            <div className="font-mono text-sm space-y-1">
              {progress.map((line, index) => (
                <div 
                  key={index} 
                  className={`${
                    line.includes('ERROR') ? 'text-red' :
                    line.includes('SUCCESS') || line.includes('completed') ? 'text-green' :
                    line.includes('INFO') ? 'text-blue' :
                    line.includes('PHASE') ? 'text-mauve' :
                    'text-subtext1'
                  }`}
                >
                  <span className="text-subtext0 mr-2">
                    {new Date().toLocaleTimeString()}
                  </span>
                  {line}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}