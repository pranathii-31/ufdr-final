import React, { useState } from 'react';
import { searchQuery } from '../api/api';
import { useLanguage } from '../context/LanguageContext';

const SearchBox = () => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const { language } = useLanguage();

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setIsLoading(true);
    setError('');
    try {
      const response = await searchQuery(query);
      setResults(response.results || []);
    } catch (err) {
      setError(err.message || 'Failed to perform search');
      setResults([]);
    } finally {
      setIsLoading(false);
    }
  };

  const renderResults = () => {
    if (isLoading) {
      return <div className="text-center py-4">Searching...</div>;
    }

    if (error) {
      return <div className="text-red-500 py-4">{error}</div>;
    }

    if (results.length === 0 && query.trim()) {
      return <div className="text-center py-4">No results found</div>;
    }

    return (
      <div className="mt-4">
        {results.map((result, index) => (
          <div key={index} className="bg-white p-4 rounded-lg shadow mb-4">
            <div className="font-semibold mb-2">
              Score: {Math.round(result.score * 100)}%
            </div>
            <div className="text-sm">{result.text}</div>
            {result.metadata && (
              <div className="text-xs text-gray-500 mt-2">
                Source: {result.metadata.source}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  const placeholder = language === 'en' 
    ? 'Enter your search query...' 
    : '搜索...';

  return (
    <div className="max-w-2xl mx-auto p-4">
      <form onSubmit={handleSearch} className="space-y-4">
        <div className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            className="flex-1 px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-400"
          >
            {isLoading ? 'Searching...' : (language === 'en' ? 'Search' : '搜索')}
          </button>
        </div>
      </form>
      {renderResults()}
    </div>
  );
};

export default SearchBox;
