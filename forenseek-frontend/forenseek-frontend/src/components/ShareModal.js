import React, { useState } from 'react';
import { X, Copy, Mail, Link, Download, Users, Lock, Globe, Share2, CheckCircle, AlertCircle } from 'lucide-react';

const ShareModal = ({ isOpen, onClose, shareData, currentUser }) => {
  const [shareType, setShareType] = useState('link'); // 'link', 'email', 'export'
  const [emailRecipients, setEmailRecipients] = useState('');
  const [shareMessage, setShareMessage] = useState('');
  const [permissions, setPermissions] = useState('view'); // 'view', 'comment', 'edit'
  const [expiryDays, setExpiryDays] = useState('7');
  const [isGenerating, setIsGenerating] = useState(false);
  const [shareLink, setShareLink] = useState('');
  const [copySuccess, setCopySuccess] = useState(false);

  if (!isOpen) return null;

  const handleShare = async () => {
    setIsGenerating(true);
    
    try {
      let result;
      
      switch (shareType) {
        case 'link':
          result = await generateShareLink();
          break;
        case 'email':
          result = await sendEmailShare();
          break;
        case 'export':
          result = await generateExport();
          break;
        default:
          throw new Error('Invalid share type');
      }
      
      if (result.success) {
        setShareLink(result.link || '');
        if (shareType === 'link') {
          setCopySuccess(true);
          setTimeout(() => setCopySuccess(false), 3000);
        }
      }
    } catch (error) {
      console.error('Share error:', error);
      alert(`Share failed: ${error.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const generateShareLink = async () => {
    const response = await fetch('http://127.0.0.1:8000/api/share/generate-link', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        data: shareData,
        permissions,
        expiry_days: parseInt(expiryDays),
        message: shareMessage
      })
    });
    
    if (!response.ok) throw new Error('Failed to generate share link');
    return await response.json();
  };

  const sendEmailShare = async () => {
    const recipients = emailRecipients.split(',').map(email => email.trim());
    
    const response = await fetch('http://127.0.0.1:8000/api/share/send-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        data: shareData,
        recipients,
        message: shareMessage,
        permissions
      })
    });
    
    if (!response.ok) throw new Error('Failed to send email share');
    return await response.json();
  };

  const generateExport = async () => {
    const response = await fetch('http://127.0.0.1:8000/api/share/generate-export', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        data: shareData,
        format: 'pdf', // or 'json', 'csv'
        include_metadata: true
      })
    });
    
    if (!response.ok) throw new Error('Failed to generate export');
    
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forenseek_share_${new Date().toISOString().split('T')[0]}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    return { success: true };
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(shareLink);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 3000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  };

  const getSharePreview = () => {
    if (!shareData) return null;
    
    return (
      <div className="bg-gray-50 p-4 rounded-lg mb-4">
        <h4 className="font-medium text-gray-900 mb-2">Share Preview</h4>
        <div className="text-sm text-gray-600">
          <p><strong>Type:</strong> {shareData.type || 'Search Results'}</p>
          <p><strong>Items:</strong> {shareData.items?.length || shareData.messages?.length || 0} entries</p>
          <p><strong>Created:</strong> {new Date().toLocaleString()}</p>
          <p><strong>Shared by:</strong> {currentUser?.email || 'Current User'}</p>
        </div>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <div className="flex items-center gap-3">
            <Share2 className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-bold text-gray-900">Share & Collaborate</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Share Type Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Choose sharing method
            </label>
            <div className="grid grid-cols-3 gap-3">
              <button
                onClick={() => setShareType('link')}
                className={`p-4 border rounded-lg text-center transition ${
                  shareType === 'link'
                    ? 'border-blue-500 bg-blue-50 text-blue-700'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <Link className="w-6 h-6 mx-auto mb-2" />
                <div className="text-sm font-medium">Share Link</div>
                <div className="text-xs text-gray-500">Generate secure link</div>
              </button>
              
              <button
                onClick={() => setShareType('email')}
                className={`p-4 border rounded-lg text-center transition ${
                  shareType === 'email'
                    ? 'border-blue-500 bg-blue-50 text-blue-700'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <Mail className="w-6 h-6 mx-auto mb-2" />
                <div className="text-sm font-medium">Email Share</div>
                <div className="text-xs text-gray-500">Send via email</div>
              </button>
              
              <button
                onClick={() => setShareType('export')}
                className={`p-4 border rounded-lg text-center transition ${
                  shareType === 'export'
                    ? 'border-blue-500 bg-blue-50 text-blue-700'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <Download className="w-6 h-6 mx-auto mb-2" />
                <div className="text-sm font-medium">Export</div>
                <div className="text-xs text-gray-500">Download file</div>
              </button>
            </div>
          </div>

          {/* Share Preview */}
          {getSharePreview()}

          {/* Email Recipients (for email share) */}
          {shareType === 'email' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Email Recipients
              </label>
              <input
                type="text"
                value={emailRecipients}
                onChange={(e) => setEmailRecipients(e.target.value)}
                placeholder="Enter email addresses separated by commas"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-500 mt-1">
                Separate multiple emails with commas
              </p>
            </div>
          )}

          {/* Share Message */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Message (Optional)
            </label>
            <textarea
              value={shareMessage}
              onChange={(e) => setShareMessage(e.target.value)}
              placeholder="Add a message to explain what you're sharing..."
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Permissions (for link and email share) */}
          {(shareType === 'link' || shareType === 'email') && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Access Permissions
              </label>
              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="radio"
                    value="view"
                    checked={permissions === 'view'}
                    onChange={(e) => setPermissions(e.target.value)}
                    className="mr-2"
                  />
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-gray-500" />
                    <span className="text-sm">View Only</span>
                  </div>
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    value="comment"
                    checked={permissions === 'comment'}
                    onChange={(e) => setPermissions(e.target.value)}
                    className="mr-2"
                  />
                  <div className="flex items-center gap-2">
                    <Users className="w-4 h-4 text-gray-500" />
                    <span className="text-sm">View & Comment</span>
                  </div>
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    value="edit"
                    checked={permissions === 'edit'}
                    onChange={(e) => setPermissions(e.target.value)}
                    className="mr-2"
                  />
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-gray-500" />
                    <span className="text-sm">Full Access</span>
                  </div>
                </label>
              </div>
            </div>
          )}

          {/* Expiry (for link share) */}
          {shareType === 'link' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Link Expiry
              </label>
              <select
                value={expiryDays}
                onChange={(e) => setExpiryDays(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="1">1 day</option>
                <option value="7">7 days</option>
                <option value="30">30 days</option>
                <option value="90">90 days</option>
                <option value="0">Never expire</option>
              </select>
            </div>
          )}

          {/* Generated Link Display */}
          {shareLink && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="text-sm font-medium text-green-800">Share link generated!</span>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={shareLink}
                  readOnly
                  className="flex-1 px-3 py-2 bg-white border border-green-300 rounded-md text-sm"
                />
                <button
                  onClick={copyToClipboard}
                  className="flex items-center gap-1 px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition text-sm"
                >
                  {copySuccess ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  {copySuccess ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-3 pt-4 border-t">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 transition"
            >
              Cancel
            </button>
            <button
              onClick={handleShare}
              disabled={isGenerating || (shareType === 'email' && !emailRecipients.trim())}
              className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isGenerating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Share2 className="w-4 h-4" />
                  {shareType === 'export' ? 'Download' : 'Share'}
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ShareModal;
