import { useState, useEffect } from 'react';

interface Generator {
  id: string;
  name: string;
  category: string;
}

interface Destination {
  id: string;
  name: string;
  type: 'hec' | 'syslog';
}

interface GenerationConfig {
  generator: string;
  destination: string;
  count: number;
  eps: number;
  continuous: boolean;
  metadata?: Record<string, any>;
}

interface EventGeneratorProps {
  apiBaseUrl?: string;
}

export default function EventGenerator({ apiBaseUrl = 'http://localhost:8001' }: EventGeneratorProps) {
  const [generators, setGenerators] = useState<Generator[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [config, setConfig] = useState<GenerationConfig>({
    generator: '',
    destination: '',
    count: 10,
    eps: 1.0,
    continuous: false,
    metadata: {}
  });
  
  const [isGenerating, setIsGenerating] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    Promise.all([fetchGenerators(), fetchDestinations()]);
  }, []);

  const fetchGenerators = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/generators?per_page=500`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      setGenerators(data.data?.generators || []);
    } catch (err) {
      setError('Failed to fetch generators');
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

  const startGeneration = async () => {
    if (!config.generator || !config.destination) {
      setError('Please select both generator and destination');
      return;
    }

    setIsGenerating(true);
    setProgress(['Starting event generation...']);
    setError('');

    try {
      // This would typically use Server-Sent Events or WebSocket
      // For now, we'll simulate the streaming with fetch
      const response = await fetch(`${apiBaseUrl}/api/v1/generate-events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          generator_id: config.generator,
          destination_id: config.destination,
          count: config.count,
          eps: config.eps,
          continuous: config.continuous,
          metadata: config.metadata
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Simulate streaming progress updates
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split('\n').filter(line => line.trim());
          
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const progressLine = line.substring(6);
              setProgress(prev => [...prev.slice(-20), progressLine]); // Keep last 20 lines
            }
          }
        }
      }

      setProgress(prev => [...prev, 'Generation completed successfully!']);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Generation failed';
      setError(errorMsg);
      setProgress(prev => [...prev, `ERROR: ${errorMsg}`]);
    } finally {
      setIsGenerating(false);
    }
  };

  const stopGeneration = () => {
    setIsGenerating(false);
    setProgress(prev => [...prev, 'Generation stopped by user']);
  };

  const clearProgress = () => {
    setProgress([]);
    setError('');
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

  const selectedGenerator = generators.find(g => g.id === config.generator);
  const selectedDestination = destinations.find(d => d.id === config.destination);

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <h2 className="text-xl font-semibold text-text mb-6">Event Generation</h2>

      {error && (
        <div className="mb-4 p-4 bg-red/10 border border-red rounded-lg">
          <p className="text-red text-sm">{error}</p>
        </div>
      )}

      {/* Configuration Form */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-subtext1 mb-2">
              Generator ({generators.length} available)
            </label>
            <select
              value={config.generator}
              onChange={(e) => setConfig({...config, generator: e.target.value})}
              disabled={isGenerating}
              className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
            >
              <option value="">Select a generator...</option>
              {generators.map(gen => (
                <option key={gen.id} value={gen.id}>
                  {gen.name} ({gen.category})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-subtext1 mb-2">
              Destination ({destinations.length} available)
            </label>
            <select
              value={config.destination}
              onChange={(e) => setConfig({...config, destination: e.target.value})}
              disabled={isGenerating}
              className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
            >
              <option value="">Select a destination...</option>
              {destinations.map(dest => (
                <option key={dest.id} value={dest.id}>
                  {dest.name} ({dest.type.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">
                Event Count
              </label>
              <input
                type="number"
                value={config.count}
                onChange={(e) => setConfig({...config, count: parseInt(e.target.value) || 0})}
                disabled={isGenerating || config.continuous}
                min="1"
                max="10000"
                className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">
                Events/Second
              </label>
              <input
                type="number"
                value={config.eps}
                onChange={(e) => setConfig({...config, eps: parseFloat(e.target.value) || 0})}
                disabled={isGenerating}
                min="0.1"
                max="1000"
                step="0.1"
                className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve disabled:opacity-50"
              />
            </div>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="continuous"
              checked={config.continuous}
              onChange={(e) => setConfig({...config, continuous: e.target.checked})}
              disabled={isGenerating}
              className="mr-2 rounded border-surface1 text-mauve focus:ring-mauve disabled:opacity-50"
            />
            <label htmlFor="continuous" className="text-sm text-subtext1">
              Continuous generation (until stopped)
            </label>
          </div>
        </div>
      </div>

      {/* Selected Configuration Preview */}
      {(selectedGenerator || selectedDestination) && (
        <div className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
          <h3 className="font-semibold text-mauve mb-2">Configuration Preview</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            {selectedGenerator && (
              <div>
                <span className="text-subtext1">Generator:</span>
                <p className="text-text font-medium">{selectedGenerator.name}</p>
                <p className="text-subtext0">{selectedGenerator.category}</p>
              </div>
            )}
            {selectedDestination && (
              <div>
                <span className="text-subtext1">Destination:</span>
                <p className="text-text font-medium">{selectedDestination.name}</p>
                <p className="text-subtext0">{selectedDestination.type.toUpperCase()}</p>
              </div>
            )}
          </div>
          <div className="mt-2 text-sm text-subtext1">
            {config.continuous 
              ? `Continuous generation at ${config.eps} EPS`
              : `Generate ${config.count} events at ${config.eps} EPS (~${Math.ceil(config.count / config.eps)}s duration)`
            }
          </div>
        </div>
      )}

      {/* Control Buttons */}
      <div className="flex gap-3 mb-6">
        <button
          onClick={startGeneration}
          disabled={isGenerating || !config.generator || !config.destination}
          className="px-6 py-2 bg-green text-base rounded-lg hover:bg-green/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isGenerating ? 'Generating...' : 'Start Generation'}
        </button>
        
        {isGenerating && (
          <button
            onClick={stopGeneration}
            className="px-6 py-2 bg-red text-base rounded-lg hover:bg-red/80 transition-colors"
          >
            Stop
          </button>
        )}
        
        <button
          onClick={clearProgress}
          disabled={isGenerating}
          className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 disabled:opacity-50 transition-colors"
        >
          Clear Log
        </button>
      </div>

      {/* Progress Log */}
      {progress.length > 0 && (
        <div className="bg-mantle rounded-lg border border-surface1 p-4">
          <div className="flex justify-between items-center mb-3">
            <h3 className="font-semibold text-text">Generation Log</h3>
            {isGenerating && (
              <div className="flex items-center text-green">
                <div className="w-2 h-2 bg-green rounded-full animate-pulse mr-2"></div>
                <span className="text-sm">Live</span>
              </div>
            )}
          </div>
          
          <div className="bg-surface0 rounded border border-surface1 p-3 max-h-64 overflow-y-auto">
            <div className="font-mono text-sm space-y-1">
              {progress.map((line, index) => (
                <div 
                  key={index} 
                  className={`${
                    line.includes('ERROR') ? 'text-red' :
                    line.includes('SUCCESS') || line.includes('completed') ? 'text-green' :
                    line.includes('INFO') ? 'text-blue' :
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