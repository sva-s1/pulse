import { useState, useRef } from 'react';

interface UploadedFile {
  id: string;
  filename: string;
  file_type: string;
  size: number;
  line_count: number;
  created_at: string;
}

interface Destination {
  id: string;
  name: string;
  type: 'hec' | 'syslog';
}

interface FileUploaderProps {
  apiBaseUrl?: string;
}

export default function FileUploader({ apiBaseUrl = 'http://localhost:8001' }: FileUploaderProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [processing, setProcessing] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const [error, setError] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [processConfig, setProcessConfig] = useState({
    destination: '',
    sourcetype: '',
    batch_size: 100,
    eps: 10.0,
    endpoint: 'event' as 'event' | 'raw'
  });

  useState(() => {
    fetchFiles();
    fetchDestinations();
  });

  const fetchFiles = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/uploads/uploads`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      setFiles(data.uploads || []);
    } catch (err) {
      setError('Failed to fetch uploaded files');
    }
  };

  const fetchDestinations = async () => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/destinations`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      setDestinations(data.destinations || []);
    } catch (err) {
      setError('Failed to fetch destinations');
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(e.dataTransfer.files);
    }
  };

  const handleFiles = async (fileList: FileList) => {
    const file = fileList[0];
    if (!file) return;

    // Validate file type
    const allowedTypes = ['.csv', '.json', '.txt', '.log', '.gz'];
    const fileExt = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!allowedTypes.includes(fileExt)) {
      setError(`Invalid file type. Allowed: ${allowedTypes.join(', ')}`);
      return;
    }

    // Validate file size (50MB limit)
    if (file.size > 50 * 1024 * 1024) {
      setError('File size must be less than 50MB');
      return;
    }

    setUploading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${apiBaseUrl}/api/v1/uploads/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      await fetchFiles(); // Refresh file list
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const processFile = async (fileId: string) => {
    if (!processConfig.destination || !processConfig.sourcetype) {
      setError('Please select destination and enter sourcetype');
      return;
    }

    setProcessing(fileId);
    setProgress(['Starting file processing...']);
    setError('');

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/uploads/process`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          upload_id: fileId,
          destination_id: processConfig.destination,
          batch_size: processConfig.batch_size,
          eps: processConfig.eps,
          sourcetype: processConfig.sourcetype,
          endpoint: processConfig.endpoint
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Stream the response for real-time progress
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split('\n').filter(line => line.trim());
          
          for (const line of lines) {
            setProgress(prev => [...prev.slice(-20), line]); // Keep last 20 lines
          }
        }
      }

      setProgress(prev => [...prev, 'File processing completed successfully!']);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Processing failed';
      setError(errorMsg);
      setProgress(prev => [...prev, `ERROR: ${errorMsg}`]);
    } finally {
      setProcessing(null);
    }
  };

  const deleteFile = async (fileId: string) => {
    if (!confirm('Are you sure you want to delete this file?')) return;

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/uploads/uploads/${fileId}`, {
        method: 'DELETE',
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      await fetchFiles(); // Refresh file list
    } catch (err) {
      setError('Failed to delete file');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="bg-surface0 rounded-lg p-6 border border-surface1">
      <h2 className="text-xl font-semibold text-text mb-6">File Upload & Processing</h2>

      {error && (
        <div className="mb-4 p-4 bg-red/10 border border-red rounded-lg">
          <p className="text-red text-sm">{error}</p>
        </div>
      )}

      {/* Upload Area */}
      <div
        className={`mb-6 border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
          dragActive 
            ? 'border-mauve bg-mauve/5' 
            : 'border-surface1 hover:border-surface2'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv,.json,.txt,.log,.gz"
          onChange={(e) => e.target.files && handleFiles(e.target.files)}
          className="hidden"
        />
        
        <div className="space-y-4">
          <div className="w-16 h-16 mx-auto bg-surface1 rounded-lg flex items-center justify-center">
            <svg className="w-8 h-8 text-subtext1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
          </div>
          
          <div>
            <p className="text-text font-medium">
              {uploading ? 'Uploading...' : 'Drop files here or click to browse'}
            </p>
            <p className="text-subtext1 text-sm mt-1">
              Supports CSV, JSON, TXT, LOG, GZ files up to 50MB
            </p>
          </div>
          
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="px-4 py-2 bg-mauve text-base rounded-lg hover:bg-mauve/80 disabled:opacity-50 transition-colors"
          >
            {uploading ? 'Uploading...' : 'Select Files'}
          </button>
        </div>
      </div>

      {/* Processing Configuration */}
      {files.length > 0 && (
        <div className="mb-6 p-4 bg-mantle rounded-lg border border-surface1">
          <h3 className="font-semibold text-text mb-4">Processing Configuration</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">Destination</label>
              <select
                value={processConfig.destination}
                onChange={(e) => setProcessConfig({...processConfig, destination: e.target.value})}
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
              >
                <option value="">Select destination...</option>
                {destinations.filter(d => d.type === 'hec').map(dest => (
                  <option key={dest.id} value={dest.id}>
                    {dest.name} (HEC)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">Sourcetype</label>
              <input
                type="text"
                value={processConfig.sourcetype}
                onChange={(e) => setProcessConfig({...processConfig, sourcetype: e.target.value})}
                placeholder="e.g., json, csv, syslog"
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">Events/Second</label>
              <input
                type="number"
                value={processConfig.eps}
                onChange={(e) => setProcessConfig({...processConfig, eps: parseFloat(e.target.value) || 0})}
                min="0.1"
                max="1000"
                step="0.1"
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-subtext1 mb-2">HEC Endpoint</label>
              <select
                value={processConfig.endpoint}
                onChange={(e) => setProcessConfig({...processConfig, endpoint: e.target.value as 'event' | 'raw'})}
                className="w-full px-3 py-2 bg-surface0 border border-surface1 rounded-lg text-text focus:outline-none focus:ring-2 focus:ring-mauve"
              >
                <option value="event">Event (JSON)</option>
                <option value="raw">Raw (Text)</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Uploaded Files List */}
      <div className="space-y-4">
        <h3 className="font-semibold text-text">Uploaded Files ({files.length})</h3>
        
        {files.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-subtext1">No files uploaded</p>
            <p className="text-subtext0 text-sm mt-1">Upload files to process and send to destinations</p>
          </div>
        ) : (
          files.map((file) => (
            <div key={file.id} className="p-4 bg-mantle rounded-lg border border-surface1">
              <div className="flex justify-between items-start mb-3">
                <div className="flex-1">
                  <h4 className="font-semibold text-text">{file.filename}</h4>
                  <div className="text-sm text-subtext1 space-y-1">
                    <p>
                      <span className="text-text">Type:</span> {file.file_type.toUpperCase()} • 
                      <span className="text-text"> Size:</span> {formatFileSize(file.size)} • 
                      <span className="text-text"> Lines:</span> {file.line_count.toLocaleString()}
                    </p>
                    <p>
                      <span className="text-text">Uploaded:</span> {new Date(file.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={() => processFile(file.id)}
                    disabled={processing === file.id || !processConfig.destination || !processConfig.sourcetype}
                    className="px-3 py-1 bg-green text-base rounded hover:bg-green/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
                  >
                    {processing === file.id ? 'Processing...' : 'Process'}
                  </button>
                  
                  <button
                    onClick={() => deleteFile(file.id)}
                    disabled={processing === file.id}
                    className="px-3 py-1 text-red hover:bg-red/10 rounded transition-colors text-sm"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Processing Progress */}
      {progress.length > 0 && (
        <div className="mt-6 bg-mantle rounded-lg border border-surface1 p-4">
          <div className="flex justify-between items-center mb-3">
            <h3 className="font-semibold text-text">Processing Log</h3>
            {processing && (
              <div className="flex items-center text-green">
                <div className="w-2 h-2 bg-green rounded-full animate-pulse mr-2"></div>
                <span className="text-sm">Processing</span>
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