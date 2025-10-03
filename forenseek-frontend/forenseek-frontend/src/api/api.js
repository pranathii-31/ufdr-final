const API_BASE = 'http://localhost:8000'; // Your backend base URL, adjust if deployed

function getAuthHeader() {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}
//Login user
export async function login(email, password) {
  const response = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    throw new Error('Login failed');
  }
  return await response.json();
}

// Signup new user
export async function signup(name, email, password) {
  const response = await fetch(`${API_BASE}/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  });
  if (!response.ok) {
    throw new Error('Signup failed');
  }
  return await response.json();
}
// Search forensic data
export async function searchQuery(query, filters = {}, language = 'en') {
  try {
    const response = await fetch(`${API_BASE}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: JSON.stringify({ query, language, ...filters }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Search failed');
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Search error:', error);
    throw new Error(error.message || 'Failed to perform search');
  }
}

// Get index status
export async function getIndexStatus() {
  try {
    const response = await fetch(`${API_BASE}/index-status`, {
      method: 'GET',
      headers: { ...getAuthHeader() },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get index status');
    }

    return await response.json();
  } catch (error) {
    console.error('Index status error:', error);
    throw new Error(error.message || 'Failed to get index status');
  }
}

// Rebuild index
export async function rebuildIndex() {
  try {
    const response = await fetch(`${API_BASE}/build_index`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Rebuild index failed');
    }

    return await response.json();
  } catch (error) {
    console.error('Rebuild index error:', error);
    throw new Error(error.message || 'Failed to rebuild index');
  }
}

// Upload files
export async function uploadFiles(files) {
  try {
    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i]);
    }

    const response = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      headers: {
        ...getAuthHeader(),
      },
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(errorData.detail || 'Upload failed');
    }

    const result = await response.json();
    console.log('Upload successful:', result);
    return {
      success: true,
      message: result.message || `Successfully uploaded ${files.length} files`,
      files: result.files
    };
  } catch (error) {
    console.error('Upload error:', error);
    throw new Error(error.message || 'Failed to upload files');
  }
}

// Get analytics
export async function getAnalytics() {
  const response = await fetch(`${API_BASE}/analytics`, {
    method: 'GET',
    headers: { ...getAuthHeader() },
  });
  if (!response.ok) {
    throw new Error('Failed to get analytics');
  }
  return await response.json();
}

// Chat history
export async function getChatHistory(sessionId) {
  const response = await fetch(`${API_BASE}/chat-history/${sessionId}`, {
    method: 'GET',
    headers: { ...getAuthHeader() },
  });
  if (!response.ok) {
    throw new Error('Failed to get chat history');
  }
  return await response.json();
}

export async function saveChatMessage(sessionId, message) {
  const response = await fetch(`${API_BASE}/chat-history/${sessionId}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader()
    },
    body: JSON.stringify(message)
  });
  if (!response.ok) {
    throw new Error('Failed to save chat message');
  }
  return await response.json();
}

export async function getAuditLogs(page = 1, pageSize = 50) {
  const response = await fetch(`${API_BASE}/audit-logs?page=${page}&page_size=${pageSize}`, {
    method: 'GET',
    headers: { ...getAuthHeader() }
  });
  if (!response.ok) {
    throw new Error('Failed to get audit logs');
  }
  return await response.json();
}

// Export PDF
export async function exportPDF(sessionId) {
  const response = await fetch(`${API_BASE}/export-pdf/${sessionId}`, {
    method: 'GET',
    headers: { ...getAuthHeader() },
  });
  if (!response.ok) {
    throw new Error('Failed to export PDF');
  }
  const blob = await response.blob();
  return blob; // caller should createObjectURL or download
}

// Get uploaded files
export async function getUploadedFiles() {
  const response = await fetch(`${API_BASE}/files`, {
    method: 'GET',
    headers: { ...getAuthHeader() },
  });
  if (!response.ok) {
    throw new Error('Failed to get files');
  }
  return await response.json();
}

// // Audit logs
// export async function getAuditLogs() {
//   const response = await fetch(`${API_BASE}/audit-logs`, {
//     method: 'GET',
//     headers: { ...getAuthHeader() },
//   });
//   if (!response.ok) {
//     throw new Error('Failed to get audit logs');
//   }
//   return await response.json();
// }
