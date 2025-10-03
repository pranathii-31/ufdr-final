import React from 'react';
import { getChatHistory } from '../api/api';

const ChatHistory = ({ sessionId }) => {
  const [messages, setMessages] = React.useState([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    const fetchChatHistory = async () => {
      if (!sessionId) return;
      
      setLoading(true);
      try {
        const history = await getChatHistory(sessionId);
        setMessages(history);
        setError(null);
      } catch (err) {
        setError('Failed to load chat history');
        console.error('Error loading chat history:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchChatHistory();
  }, [sessionId]);

  if (loading) {
    return <div className="p-4">Loading chat history...</div>;
  }

  if (error) {
    return <div className="p-4 text-red-600">{error}</div>;
  }

  return (
    <div className="chat-history p-4">
      {messages.length === 0 ? (
        <div className="text-gray-500">No messages yet</div>
      ) : (
        <div className="space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`p-3 rounded-lg ${
                message.isUser
                  ? 'bg-blue-100 ml-auto'
                  : 'bg-gray-100'
              }`}
              style={{ maxWidth: '80%' }}
            >
              <div className="text-sm text-gray-600 mb-1">
                {message.isUser ? 'You' : 'Assistant'}
              </div>
              <div className="break-words">
                {message.content}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ChatHistory;