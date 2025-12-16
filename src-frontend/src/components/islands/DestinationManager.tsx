import { useState, useEffect } from 'react';

interface Destination {
  id: string;
  name: string;
  type: 'hec' | 'syslog';
  url?: string;
  ip?: string;
  port?: number;
  protocol?: 'TCP' | 'UDP';
  created_at: string;
}

interface DestinationManagerProps {
  apiBaseUrl?: string;
}

export default function DestinationManager({ apiBaseUrl = 'http://localhost:8001' }: DestinationManagerProps) {
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    type: 'hec' as 'hec' | 'syslog',
    url: '',
    ip: '',
    port: '',
    protocol: 'TCP' as 'TCP' | 'UDP'
  });

  useEffect(() => {
    fetchDestinations();
  }, []);

  const fetchDestinations = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${apiBaseUrl}/api/v1/destinations`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setDestinations(data.destinations || []);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch destinations');
      console.error('Failed to fetch destinations:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const payload = {
        name: formData.name,
        type: formData.type,
        ...(formData.type === 'hec' 
          ? { url: formData.url }
          : { 
              ip: formData.ip, 
              port: parseInt(formData.port), 
              protocol: formData.protocol 
            }
        )
      };

      const response = await fetch(`${apiBaseUrl}/api/v1/destinations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      // Reset form and refresh list
      setFormData({
        name: '',
        type: 'hec',
        url: '',
        ip: '',
        port: '',
        protocol: 'TCP'
      });
      setShowAddForm(false);
      await fetchDestinations();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create destination');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this destination?')) return;

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/destinations/${id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      await fetchDestinations();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete destination');
    }
  };

  if (loading) {
    return (
      <div className="bg-surface0 rounded-lg p-6 border border-surface1">
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-surface1 rounded w-1/3"></div>
          <div className="h-4 bg-surface1 rounded w-full"></div>
          <div className="h-4 bg-surface1 rounded w-2/3"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-semibold text-text">Destinations</h2>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-4 py-2 bg-mauve text-base rounded-lg hover:bg-mauve/80 transition-colors"
        >
          {showAddForm ? 'Cancel' : 'Add Destination'}
        </button>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red/10 border border-red rounded-lg">
          <p className="text-red text-sm">{error}</p>
        </div>
      )}

      {/* Add Form */}
      {showAddForm && (
        <form onSubmit={handleSubmit} className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
          <h3 className="text-lg font-semibold text-text mb-4">Add New Destination</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">Type</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({...formData, type: e.target.value as 'hec' | 'syslog'})}
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
              >
                <option value="hec">SDL HEC</option>
                <option value="syslog">Syslog Server</option>
              </select>
            </div>
          </div>

          {formData.type === 'hec' ? (
            <div className="mb-4">
              <label className="block text-sm font-medium text-subtext1 mb-2">SDL HEC URL</label>
              <input
                type="url"
                value={formData.url}
                onChange={(e) => setFormData({...formData, url: e.target.value})}
                placeholder="https://your-instance.sentinelone.net:443/api/v1/cloud_connect/events/raw"
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
                required
              />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-subtext1 mb-2">IP Address</label>
                <input
                  type="text"
                  value={formData.ip}
                  onChange={(e) => setFormData({...formData, ip: e.target.value})}
                  placeholder="192.168.1.100"
                  className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-subtext1 mb-2">Port</label>
                <input
                  type="number"
                  value={formData.port}
                  onChange={(e) => setFormData({...formData, port: e.target.value})}
                  placeholder="514"
                  className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-subtext1 mb-2">Protocol</label>
                <select
                  value={formData.protocol}
                  onChange={(e) => setFormData({...formData, protocol: e.target.value as 'TCP' | 'UDP'})}
                  className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
                >
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                </select>
              </div>
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="submit"
              className="px-4 py-2 bg-green text-base rounded-lg hover:bg-green/80 transition-colors"
            >
              Create Destination
            </button>
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-4 py-2 bg-surface1 text-text rounded-lg hover:bg-surface2 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Destinations List */}
      <div className="space-y-4">
        {destinations.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-subtext1">No destinations configured</p>
            <p className="text-subtext0 text-sm mt-1">Add a destination to start sending events</p>
          </div>
        ) : (
          destinations.map((dest) => (
            <div key={dest.id} className="p-4 bg-mantle rounded-lg border border-surface1">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-semibold text-text">{dest.name}</h3>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      dest.type === 'hec' 
                        ? 'bg-blue/20 text-blue' 
                        : 'bg-green/20 text-green'
                    }`}>
                      {dest.type.toUpperCase()}
                    </span>
                  </div>
                  
                  <div className="text-sm text-subtext1 space-y-1">
                    {dest.type === 'hec' ? (
                      <p><span className="text-text">URL:</span> {dest.url}</p>
                    ) : (
                      <>
                        <p><span className="text-text">Address:</span> {dest.ip}:{dest.port}</p>
                        <p><span className="text-text">Protocol:</span> {dest.protocol}</p>
                      </>
                    )}
                    <p><span className="text-text">Created:</span> {new Date(dest.created_at).toLocaleDateString()}</p>
                  </div>
                </div>
                
                <button
                  onClick={() => handleDelete(dest.id)}
                  className="px-3 py-1 text-red hover:bg-red/10 rounded transition-colors"
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}