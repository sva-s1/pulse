import { useState, useEffect } from 'react';

interface Generator {
  id: string;
  name: string;
  category: string;
  file_path: string;
}

interface GeneratorSelectorProps {
  apiBaseUrl?: string;
}

export default function GeneratorSelector({ apiBaseUrl = 'http://localhost:8001' }: GeneratorSelectorProps) {
  const [generators, setGenerators] = useState<Generator[]>([]);
  const [selectedGenerator, setSelectedGenerator] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  // Get unique categories
  const categories = [...new Set(generators.map(g => g.category))].sort();
  
  // Filter generators by selected category
  const filteredGenerators = selectedCategory 
    ? generators.filter(g => g.category === selectedCategory)
    : generators;

  useEffect(() => {
    fetchGenerators();
  }, []);

  const fetchGenerators = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${apiBaseUrl}/api/v1/generators?per_page=500`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      const generatorList = data.data?.generators || [];
      setGenerators(generatorList);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch generators');
      console.error('Failed to fetch generators:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCategoryChange = (category: string) => {
    setSelectedCategory(category);
    setSelectedGenerator(''); // Reset generator selection when category changes
  };

  if (loading) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-surface1">
        <div className="animate-pulse">
          <div className="h-4 bg-surface1 rounded w-1/4 mb-4"></div>
          <div className="h-10 bg-surface1 rounded mb-4"></div>
          <div className="h-4 bg-surface1 rounded w-1/4 mb-4"></div>
          <div className="h-10 bg-surface1 rounded"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-red">
        <div className="flex items-center mb-4">
          <svg className="w-5 h-5 text-red mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          <h3 className="text-lg font-semibold text-red">Connection Error</h3>
        </div>
        <p className="text-subtext1 mb-4">{error}</p>
        <button 
          onClick={fetchGenerators}
          className="px-4 py-2 bg-red text-base rounded-lg hover:bg-red/80 transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <h2 className="text-xl font-semibold text-text mb-6">Select Security Event Generator</h2>
      
      {/* Category Selection */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-subtext1 mb-2">
          Category ({categories.length} available)
        </label>
        <select
          value={selectedCategory}
          onChange={(e) => handleCategoryChange(e.target.value)}
          className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve focus:border-transparent"
        >
          <option value="">All Categories ({generators.length} generators)</option>
          {categories.map(category => {
            const count = generators.filter(g => g.category === category).length;
            return (
              <option key={category} value={category}>
                {category} ({count} generators)
              </option>
            );
          })}
        </select>
      </div>

      {/* Generator Selection */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-subtext1 mb-2">
          Generator ({filteredGenerators.length} available)
        </label>
        <select
          value={selectedGenerator}
          onChange={(e) => setSelectedGenerator(e.target.value)}
          disabled={filteredGenerators.length === 0}
          className="w-full px-3 py-2 bg-mantle border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <option value="">
            {filteredGenerators.length === 0 
              ? 'No generators available' 
              : 'Select a generator...'
            }
          </option>
          {filteredGenerators.map(generator => (
            <option key={generator.id} value={generator.id}>
              {generator.name}
            </option>
          ))}
        </select>
      </div>

      {/* Selected Generator Info */}
      {selectedGenerator && (
        <div className="bg-mantle rounded-lg p-4 border border-surface1">
          {(() => {
            const generator = generators.find(g => g.id === selectedGenerator);
            return generator ? (
              <div>
                <h3 className="font-semibold text-mauve mb-2">{generator.name}</h3>
                <div className="text-sm text-subtext1 space-y-1">
                  <p><span className="text-text">Category:</span> {generator.category}</p>
                  <p><span className="text-text">ID:</span> {generator.id}</p>
                  <p><span className="text-text">File:</span> {generator.file_path}</p>
                </div>
              </div>
            ) : null;
          })()}
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex gap-3 mt-6">
        <button
          disabled={!selectedGenerator}
          className="flex-1 px-4 py-2 bg-mauve text-base rounded-lg hover:bg-mauve/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Configure Generation
        </button>
        <button
          onClick={fetchGenerators}
          className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 transition-colors"
        >
          Refresh
        </button>
      </div>
    </div>
  );
}