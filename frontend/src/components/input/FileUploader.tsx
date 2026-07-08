import React, { useCallback, useState } from 'react';
import { UploadCloud, FileText } from 'lucide-react';
import './FileUploader.css';

interface FileUploaderProps {
  onFileSelect: (file: File) => void;
}

const FileUploader: React.FC<FileUploaderProps> = ({ onFileSelect }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleFile = useCallback((file: File) => {
    if (file.name.endsWith('.eml') || file.name.endsWith('.txt')) {
      setSelectedFile(file);
      onFileSelect(file);
    } else {
      alert("Invalid file type. Please upload a .eml or .txt file.");
    }
  }, [onFileSelect]);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setIsDragging(true);
    } else if (e.type === 'dragleave') {
      setIsDragging(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      handleFile(file);
    }
  }, [handleFile]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  return (
    <div 
      className={`file-uploader ${isDragging ? 'drag-active' : ''}`}
      onDragEnter={handleDrag}
      onDragLeave={handleDrag}
      onDragOver={handleDrag}
      onDrop={handleDrop}
    >
      <input 
        type="file" 
        accept=".eml,.txt" 
        onChange={handleChange} 
        id="file-upload" 
        className="hidden-input" 
      />
      
      <label htmlFor="file-upload" className="upload-label">
        {selectedFile ? (
          <div className="file-selected">
            <FileText size={48} color="var(--primary)" />
            <p className="file-name">{selectedFile.name}</p>
            <p className="file-size">{(selectedFile.size / 1024).toFixed(2)} KB</p>
          </div>
        ) : (
          <div className="upload-prompt">
            <UploadCloud size={48} color="var(--text-muted)" />
            <p className="upload-text"><strong>Click to upload</strong> or drag and drop</p>
            <p className="upload-hint">Supported formats: .eml, .txt</p>
          </div>
        )}
      </label>
    </div>
  );
};

export default FileUploader;
