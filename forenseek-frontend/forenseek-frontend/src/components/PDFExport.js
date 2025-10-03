import React, { useState } from 'react';
import { uploadFiles } from '../api/api';
import { useLanguage } from '../context/LanguageContext';

const PDFExport = () => {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
  const { language } = useLanguage();

  const handleFileChange = (e) => {
    setFiles(Array.from(e.target.files));
    setUploadStatus(null);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (files.length === 0) {
      setUploadStatus({
        success: false,
        message: language === 'en' ? 'Please select files to upload' : '请选择要上传的文件'
      });
      return;
    }

    setUploading(true);
    setUploadStatus(null);

    try {
      const result = await uploadFiles(files);
      console.log('Upload result:', result);
      setUploadStatus({
        success: true,
        message: language === 'en' 
          ? result.message || `Successfully uploaded ${files.length} file(s)` 
          : `成功上传 ${files.length} 个文件`,
        details: result
      });
      setFiles([]);
      // Clear the file input
      e.target.reset();
      
      // Show a browser notification if supported
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification(language === 'en' ? 'Files Uploaded' : '文件已上传', {
          body: language === 'en' 
            ? `Successfully uploaded ${files.length} file(s)` 
            : `成功上传 ${files.length} 个文件`
        });
      }
    } catch (error) {
      setUploadStatus({
        success: false,
        message: error.message || (language === 'en' 
          ? 'Failed to upload files' 
          : '文件上传失败')
      });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <form onSubmit={handleUpload} className="space-y-4">
        <div className="flex flex-col gap-4">
          <input
            type="file"
            onChange={handleFileChange}
            multiple
            accept=".json"
            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
          />
          <button
            type="submit"
            disabled={uploading || files.length === 0}
            className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-400"
          >
            {uploading 
              ? (language === 'en' ? 'Uploading...' : '上传中...') 
              : (language === 'en' ? 'Upload Files' : '上传文件')}
          </button>
        </div>
      </form>

      {files.length > 0 && (
        <div className="mt-4">
          <h3 className="font-semibold mb-2">
            {language === 'en' ? 'Selected Files:' : '已选择文件：'}
          </h3>
          <ul className="list-disc list-inside">
            {files.map((file, index) => (
              <li key={index} className="text-sm text-gray-600">{file.name}</li>
            ))}
          </ul>
        </div>
      )}

      {uploadStatus && (
        <div className={`mt-4 p-4 rounded-lg ${uploadStatus.success ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
          <p className="font-semibold">{uploadStatus.message}</p>
          {uploadStatus.success && uploadStatus.details && (
            <p className="text-sm mt-2">
              {language === 'en' ? 'Processing files...' : '正在处理文件...'}
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default PDFExport;
