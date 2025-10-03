/* global webkitSpeechRecognition */
import React, { useState } from 'react';
import { Search, Shield, Bell, Volume2, Filter, Download, Upload, Share2, Mic, LogOut, BarChart3, FileText, User, Settings, Clock } from 'lucide-react';
import { 
  login, signup, searchQuery as searchApi, rebuildIndex, uploadFiles, 
  exportPDF, getAnalytics, saveChatMessage, getAuditLogs 
} from './api/api';
import ChatHistory from './components/ChatHistory';
import { useLanguage } from './context/LanguageContext';



const ForenseekApp = () => {
  const [user, setUser] = useState(null);
  const { language, setLanguage, translations: t } = useLanguage();
  const [activeView, setActiveView] = useState('login'); // Sign in shows first
  const [queryText, setQueryText] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState([
    { id: 1, message: 'New case assigned: #2024-045', time: '5m ago', read: false },
    { id: 2, message: 'Index rebuild completed', time: '1h ago', read: true }
  ]);
  const [filters, setFilters] = useState({
    dateFrom: '',
    dateTo: '',
    caseType: '',
    minRelevance: 0
  });
  const [chatMessages, setChatMessages] = useState([]);
  const [voiceActive, setVoiceActive] = useState(false);
  const [gpsPoints, setGpsPoints] = useState([]);
  const [assistantText, setAssistantText] = useState('');
  const [analyticsData, setAnalyticsData] = useState(null);
  const [latestSessionId, setLatestSessionId] = useState(null);

  const handleLogin = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');
    setLoading(true);
    try {
      const response = await login(email, password);
      console.log("Logged in user:", response.user);
      setUser(response.user);
      setActiveView('search'); // Redirect to main page view on login success
      localStorage.setItem('token', response.token);
    } catch (error) {
      console.error("Login error:", error);
      alert('Login failed: ' + (error.message || 'Unknown error'));
    }
    setLoading(false);
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const name = formData.get('name');
    const email = formData.get('email');
    const password = formData.get('password');
    setLoading(true);
    try {
      await signup(name, email, password);
      setActiveView('login');  // Switch to login after successful signup
      alert('Signup successful! Please sign in.');
    } catch (error) {
      console.error("Signup error:", error);
      alert('Signup failed: ' + (error.message || 'Unknown error'));
    }
    setLoading(false);
  };

  const handleLogout = () => {
    setUser(null);
    setActiveView('login'); // Show login page after logout
    localStorage.removeItem('token');
  };

  const handleSearch = async (e) => {
    e?.preventDefault();
    if (!queryText.trim()) {
      alert('Please enter a search query');
      return;
    }
    setLoading(true);
    try {
      console.log('Searching for:', queryText);
      const response = await searchApi(queryText, filters, language);
      console.log('Search response:', response);
      
      // Backend returns answer, sources, gps, session_id
      let results = response.sources || [];
      const gps = response.gps || [];
      setAssistantText(response.answer || '');
      
      // If no structured sources but we do have an answer, surface it as a synthetic card
      if (results.length === 0 && response.answer) {
        results = [{
          id: 'answer',
          title: 'Answer',
          snippet: response.answer,
          relevance: 1,
          date: '',
          type: 'Response'
        }];
      }

      setGpsPoints(gps);
      setSearchResults(results);
      
      const newChat = [
        { type: 'user', text: queryText },
        { type: 'ai', text: response.answer, results, session_id: response.session_id }
      ];
      
      setChatMessages(prev => ([...prev, ...newChat]));
      
      // persist chat to backend
      try {
        await saveChatMessage(response.session_id, { query: queryText, answer: response.answer, sources: results });
      } catch (err) {
        console.warn('Failed to save chat message', err);
      }
      // persist latest session id to state so export/tts can use it
      setLatestSessionId(response.session_id || null);
      // show notification
      setNotifications(prev => [{ id: Date.now(), message: `Search complete: ${results.length} items`, time: 'now', read: false }, ...prev]);
    } catch (error) {
      alert('Search failed');
    }
    setLoading(false);
  };

  const downloadBlob = (blob, filename) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // Dynamically load Leaflet CSS/JS when gpsPoints change and render map
  React.useEffect(() => {
    if (!gpsPoints || gpsPoints.length === 0) return;
    const L_CSS = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
    const L_JS = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';

    // add css
    if (!document.querySelector(`link[href="${L_CSS}"]`)) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = L_CSS;
      document.head.appendChild(link);
    }

    // load script
    function loadScript(src, cb) {
      if (document.querySelector(`script[src="${src}"]`)) return cb();
      const s = document.createElement('script');
      s.src = src;
      s.onload = cb;
      document.body.appendChild(s);
    }

    loadScript(L_JS, () => {
      // eslint-disable-next-line no-undef
      const L = window.L;
      if (!L) return;
      const mapEl = document.getElementById('map');
      if (!mapEl) return;
      // clear previous
      if (mapEl._leaflet_id) {
        try { mapEl._leaflet_id = null; mapEl.innerHTML = ''; } catch(e) {}
      }
      const map = L.map('map').setView([gpsPoints[0].lat, gpsPoints[0].lon], 8);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '© OpenStreetMap'
      }).addTo(map);
      gpsPoints.forEach(p => {
        L.marker([p.lat, p.lon]).addTo(map).bindPopup(p.source || 'point');
      });
    });

  }, [gpsPoints]);

  React.useEffect(() => {
    if (activeView === 'analytics') loadAnalytics();
    if (activeView === 'audit') loadAuditLogs();
  }, [activeView]);

  const handleUpload = async (ev) => {
    if (!user) { alert('Please login first'); return; }
    const files = ev.target.files;
    if (!files || files.length === 0) return;
    setLoading(true);
    try {
      // Show upload started notification
      alert(`Starting upload of ${files.length} files...`);
      
      const resp = await uploadFiles(files);
      console.log('Upload response:', resp);

      // Show success notification
      alert(resp.message || `Successfully uploaded ${files.length} files!`);
      
      // Add to notifications panel
      setNotifications(prev => [{
        id: Date.now(),
        message: resp.message || `Successfully uploaded ${resp.files.length} files`,
        time: 'now',
        read: false
      }, ...prev]);

      // Rebuild index automatically after upload
      try {
        await rebuildIndex();
        alert('Index rebuilt successfully!');
      } catch (indexError) {
        console.error('Index rebuild error:', indexError);
        alert('Files uploaded but index rebuild failed. Please rebuild manually.');
      }

      // refresh analytics
      const a = await getAnalytics();
      console.log('analytics', a);
    } catch (err) {
      console.error('Upload error:', err);
      alert('Upload failed: ' + (err.message || 'Unknown error'));
    }
    setLoading(false);
  };

  const handleExportPDF = async () => {
    if (!user) { alert('Please login first'); return; }
    // open PDF via API for current session (last chat)
    const lastSession = latestSessionId || (chatMessages.length ? chatMessages[chatMessages.length-1].session_id : null);
    if (!lastSession) {
      alert('No session available to export');
      return;
    }
    try {
      const blob = await exportPDF(lastSession);
      downloadBlob(blob, `session_${lastSession}.pdf`);
      setNotifications(prev => [{ id: Date.now(), message: `PDF exported for session ${lastSession}`, time: 'now', read: false }, ...prev]);
    } catch (err) {
      alert('PDF export failed');
    }
  };

  const [auditLogs, setAuditLogs] = useState([]);
  const loadAuditLogs = async () => {
    if (!user) { setAuditLogs([]); return; }
    try {
      const logs = await getAuditLogs();
      setAuditLogs(logs);
    } catch (e) {
      console.error('Failed to load audit logs', e);
    }
  };

  const handleTextToSpeech = (text) => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = language === 'es' ? 'es-ES' : language === 'fr' ? 'fr-FR' : 'en-US';
      speechSynthesis.speak(utterance);
    }
  };

  // eslint-disable-next-line no-restricted-globals
  const handleRebuildIndex = async () => {
    // eslint-disable-next-line no-restricted-globals
    if (!confirm('Rebuild search index? This may take several minutes.')) return;
    setLoading(true);
    try {
      await rebuildIndex();
      alert('Index rebuilt successfully');
    } catch (error) {
      alert('Index rebuild failed');
    }
    setLoading(false);
  };

  const loadAnalytics = async () => {
    try {
      const a = await getAnalytics();
      setAnalyticsData(a);
    } catch (e) {
      console.error('Failed to load analytics', e);
    }
  };

  const handleVoiceInput = () => {
    if ('webkitSpeechRecognition' in window) {
      const recognition = new webkitSpeechRecognition();
      recognition.lang = language === 'es' ? 'es-ES' : language === 'fr' ? 'fr-FR' : 'en-US';
      recognition.onstart = () => setVoiceActive(true);
      recognition.onend = () => setVoiceActive(false);
      recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setQueryText(transcript);
      };
      recognition.start();
    } else {
      alert('Voice recognition not supported in this browser');
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-8">
          <div className="text-center mb-8">
            <Shield className="w-16 h-16 mx-auto text-blue-600 mb-4" />
            <h1 className="text-3xl font-bold text-gray-900">{t.appName}</h1>
            <p className="text-gray-600 mt-2">Forensic Intelligence Platform</p>
          </div>
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => setActiveView('login')}
              className={`flex-1 py-2 rounded-lg font-medium transition ${activeView === 'login' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'}`}>
              {t.login}
            </button>
            <button
              onClick={() => setActiveView('signup')}
              className={`flex-1 py-2 rounded-lg font-medium transition ${activeView === 'signup' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'}`}>
              {t.signup}
            </button>
          </div>
          {activeView === 'login' ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">{t.email}</label>
                <input type="email" name="email" required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">{t.password}</label>
                <input type="password" name="password" required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <button type="submit" disabled={loading}
                className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition disabled:opacity-50">
                {loading ? 'Loading...' : t.login}
              </button>
            </form>
          ) : (
            <form onSubmit={handleSignup} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">{t.name}</label>
                <input type="text" name="name" required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">{t.email}</label>
                <input type="email" name="email" required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">{t.password}</label>
                <input type="password" name="password" required
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <button type="submit" disabled={loading}
                className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition disabled:opacity-50">
                {loading ? 'Loading...' : t.signup}
              </button>
            </form>
          )}
          <div className="flex justify-center gap-2 mt-6">
            {['en', 'es', 'fr'].map(lang => (
              <button key={lang} onClick={() => setLanguage(lang)}
                className={`px-4 py-2 rounded-lg font-medium transition ${language === lang ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-600'}`}>
                {lang.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Main App Screen after login
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gradient-to-r from-blue-900 to-blue-700 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8" />
            <h1 className="text-2xl font-bold">{t.appName}</h1>
            <span className="text-sm bg-blue-800 px-3 py-1 rounded-full">{user.role}</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="relative">
              <button onClick={() => setShowNotifications(!showNotifications)}
                className="p-2 hover:bg-blue-800 rounded-lg transition relative">
                <Bell className="w-5 h-5" />
                {notifications.some(n => !n.read) && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
                )}
              </button>
              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-xl z-50">
                  <div className="p-4 border-b">
                    <h3 className="font-bold text-gray-900">{t.notifications}</h3>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.map(notif => (
                      <div key={notif.id} className={`p-4 border-b hover:bg-gray-50 ${!notif.read ? 'bg-blue-50' : ''}`}>
                        <p className="text-sm text-gray-900">{notif.message}</p>
                        <p className="text-xs text-gray-500 mt-1">{notif.time}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            <select value={language} onChange={e => setLanguage(e.target.value)} className="bg-blue-800 border-none rounded-lg px-3 py-2 text-sm">
              <option value="en">English</option>
              <option value="es">Español</option>
              <option value="fr">Français</option>
            </select>
            <button onClick={handleLogout} className="flex items-center gap-2 px-4 py-2 bg-blue-800 hover:bg-blue-900 rounded-lg transition">
              <LogOut className="w-4 h-4" />
              {t.logout}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-6 grid grid-cols-12 gap-6">
        {/* Sidebar */}
        <aside className="col-span-3 space-y-2">
          <button onClick={() => setActiveView('search')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${activeView === 'search' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}>
            <Search className="w-5 h-5" />
            {t.search}
          </button>
          <button onClick={() => setActiveView('analytics')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${activeView === 'analytics' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}>
            <BarChart3 className="w-5 h-5" />
            {t.analytics}
          </button>
          <button onClick={() => setActiveView('audit')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${activeView === 'audit' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}>
            <FileText className="w-5 h-5" />
            {t.auditLogs}
          </button>
          <button onClick={() => setActiveView('profile')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition ${activeView === 'profile' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}>
            <User className="w-5 h-5" />
            {t.profile}
          </button>
          <div className="pt-4 border-t">
            <button onClick={handleRebuildIndex} 
              className="w-full flex items-center gap-3 px-4 py-3 bg-yellow-50 text-yellow-700 rounded-lg hover:bg-yellow-100 transition">
              <Settings className="w-5 h-5" />
              {t.rebuildIndex}
            </button>
          </div>
        </aside>

        {/* Main Area */}
        <main className="col-span-9">
          {activeView === 'search' && (
            <div className="space-y-6">
              {/* Search bar */}
              <div className="bg-white rounded-lg shadow-md p-6">
                <form onSubmit={handleSearch} className="space-y-4">
                  <div className="flex gap-2">
                    <div className="flex-1 relative">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                      <input type="text" value={queryText} onChange={e => setQueryText(e.target.value)}
                        placeholder={t.searchPlaceholder}
                        className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
                    </div>
                    <button type="button" onClick={handleVoiceInput}
                      className={`p-3 rounded-lg transition ${voiceActive ? 'bg-red-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'}`}>
                      <Mic className="w-5 h-5" />
                    </button>
                    <button type="submit" disabled={loading}
                      className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:opacity-50">
                      {loading ? 'Searching...' : t.search}
                    </button>
                  </div>

                  <div className="flex gap-2">
                    <button type="button" onClick={() => setShowFilters(!showFilters)}
                      className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition">
                      <Filter className="w-4 h-4" />
                      {t.advancedFilters}
                    </button>
                    <button type="button" onClick={handleExportPDF}
                      className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition">
                      <Download className="w-4 h-4" />
                      {t.export}
                    </button>
                    <label className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition cursor-pointer">
                      <Upload className="w-4 h-4" />
                      {t.upload}
                      <input type="file" multiple onChange={handleUpload} className="hidden" />
                    </label>
                    <button type="button"
                      className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition">
                      <Share2 className="w-4 h-4" />
                      {t.collaborate}
                    </button>
                  </div>

                  {showFilters && (
                    <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">{t.dateRange} (From)</label>
                        <input type="date" value={filters.dateFrom} onChange={e => setFilters({ ...filters, dateFrom: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">{t.dateRange} (To)</label>
                        <input type="date" value={filters.dateTo} onChange={e => setFilters({ ...filters, dateTo: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">{t.caseType}</label>
                        <select value={filters.caseType} onChange={e => setFilters({ ...filters, caseType: e.target.value })}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg">
                          <option value="">All Types</option>
                          <option value="fraud">Fraud</option>
                          <option value="cyber">Cybercrime</option>
                          <option value="homicide">Homicide</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">Min {t.relevance}</label>
                        <input type="range" min="0" max="100" value={filters.minRelevance} onChange={e => setFilters({ ...filters, minRelevance: e.target.value })}
                          className="w-full" />
                        <span className="text-sm text-gray-600">{filters.minRelevance}%</span>
                      </div>
                    </div>
                  )}
                </form>
              </div>

              {/* Assistant answer */}
              {assistantText && (
                <div className="bg-white rounded-lg shadow-md p-6">
                  <h2 className="text-xl font-bold text-gray-900 mb-2">Assistant</h2>
                  <p className="whitespace-pre-line text-gray-800">{assistantText}</p>
                </div>
              )}

              {/* Search results */}
              {searchResults.length > 0 && (
                <div className="bg-white rounded-lg shadow-md p-6">
                  <h2 className="text-xl font-bold text-gray-900 mb-4">{t.results} ({searchResults.length})</h2>
                  <div className="space-y-4">
                    {searchResults.map(result => (
                      <div key={result.id} className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 transition cursor-pointer">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h3 className="font-bold text-gray-900 mb-1">{result.title}</h3>
                            <p className="text-sm text-gray-600 mb-2">{result.snippet}</p>
                            <div className="flex items-center gap-4 text-xs text-gray-500">
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {result.date}
                              </span>
                              <span className="flex items-center gap-1">
                                {t.relevance}: {(result.relevance * 100).toFixed(0)}%
                              </span>
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <button onClick={() => handleTextToSpeech(result.snippet)} className="p-2 text-gray-600 hover:text-blue-600 transition">
                              <Volume2 className="w-4 h-4" />
                            </button>
                            <button className="p-2 text-gray-600 hover:text-blue-600 transition">
                              <Share2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* GPS Map */}
              {gpsPoints && gpsPoints.length > 0 && (
                <div className="bg-white rounded-lg shadow-md p-6 mt-4">
                  <h2 className="text-xl font-bold text-gray-900 mb-4">Location Map</h2>
                  <div id="map" style={{ height: 400 }}></div>
                </div>
              )}
            </div>
          )}

          {activeView === 'analytics' && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold text-gray-900 mb-6">{t.analytics}</h2>
              <div className="grid grid-cols-3 gap-6 mb-8">
                <div className="p-6 bg-blue-50 rounded-lg">
                  <div className="text-3xl font-bold text-blue-600 mb-2">{analyticsData ? analyticsData.cases : '—'}</div>
                  <div className="text-sm text-gray-600">Total Cases</div>
                </div>
                <div className="p-6 bg-green-50 rounded-lg">
                  <div className="text-3xl font-bold text-green-600 mb-2">{analyticsData ? analyticsData.total_files : '—'}</div>
                  <div className="text-sm text-gray-600">Uploaded Files</div>
                </div>
                <div className="p-6 bg-purple-50 rounded-lg">
                  <div className="text-3xl font-bold text-purple-600 mb-2">{analyticsData ? ((analyticsData.cases && analyticsData.total_files) ? ((analyticsData.cases / Math.max(analyticsData.total_files,1))*100).toFixed(1) + '%' : '—') : '—'}</div>
                  <div className="text-sm text-gray-600">Cases / File Avg</div>
                </div>
              </div>
              <div className="space-y-4">
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Fraud Cases</span>
                    <span className="text-sm text-gray-600">{analyticsData && analyticsData.types && analyticsData.types.fraud ? `${analyticsData.types.fraud} (${((analyticsData.types.fraud/(analyticsData.cases||1))*100).toFixed(1)}%)` : '—'}</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div className="bg-blue-600 h-2 rounded-full" style={{ width: '36.6%' }}></div>
                  </div>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Cybercrime</span>
                    <span className="text-sm text-gray-600">389 (31.2%)</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div className="bg-green-600 h-2 rounded-full" style={{ width: '31.2%' }}></div>
                  </div>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-700">Other Cases</span>
                    <span className="text-sm text-gray-600">402 (32.2%)</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div className="bg-purple-600 h-2 rounded-full" style={{ width: '32.2%' }}></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeView === 'audit' && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold text-gray-900 mb-6">{t.auditLogs}</h2>
              <div className="space-y-3">
                {[
                  { user: 'John Doe', action: 'Searched for "financial fraud"', timestamp: '2024-10-01 14:32:15', ip: '192.168.1.100' },
                  { user: 'Jane Smith', action: 'Exported case #2024-045', timestamp: '2024-10-01 14:28:42', ip: '192.168.1.101' },
                  { user: 'Admin', action: 'Rebuilt search index', timestamp: '2024-10-01 13:15:00', ip: '192.168.1.1' },
                  { user: 'John Doe', action: 'Uploaded document: evidence_log.pdf', timestamp: '2024-10-01 12:45:33', ip: '192.168.1.100' },
                  { user: 'Mike Johnson', action: 'Modified case #2024-043', timestamp: '2024-10-01 11:20:18', ip: '192.168.1.102' },
                ].map((log, idx) => (
                  <div key={idx} className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <User className="w-4 h-4 text-gray-500" />
                          <span className="font-medium text-gray-900">{log.user}</span>
                        </div>
                        <p className="text-sm text-gray-700">{log.action}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {log.timestamp}
                          </span>
                          <span>IP: {log.ip}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeView === 'profile' && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold text-gray-900 mb-6">{t.profile}</h2>
              <div className="space-y-6">
                <div className="flex items-center gap-6">
                  <div className="w-24 h-24 bg-blue-600 rounded-full flex items-center justify-center text-white text-3xl font-bold">
                    {user.name.charAt(0)}
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-gray-900">{user.name}</h3>
                    <p className="text-gray-600">{user.email}</p>
                    <span className="inline-block mt-2 px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-sm font-medium">
                      {user.role}
                    </span>
                  </div>
                </div>

                <div className="border-t pt-6">
                  <h4 className="font-bold text-gray-900 mb-4">Account Settings</h4>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                      <input type="text" defaultValue={user.name}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                      <input type="email" defaultValue={user.email}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">New Password</label>
                      <input type="password" placeholder="Leave blank to keep current password"
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <button className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">Save Changes</button>
                  </div>
                </div>

                <div className="border-t pt-6">
                  <h4 className="font-bold text-gray-900 mb-4">Activity Summary</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-gray-900">127</div>
                      <div className="text-sm text-gray-600">Searches This Month</div>
                    </div>
                    <div className="p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-gray-900">34</div>
                      <div className="text-sm text-gray-600">Cases Accessed</div>
                    </div>
                    <div className="p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-gray-900">12</div>
                      <div className="text-sm text-gray-600">Documents Uploaded</div>
                    </div>
                    <div className="p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-gray-900">8</div>
                      <div className="text-sm text-gray-600">Collaborations</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        </main>
      </div>
    </div>
  );
};
 

export default ForenseekApp;

