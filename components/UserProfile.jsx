'use client';

import React, { useState, useEffect } from 'react';
#
function UserProfile({ userId }) {
  const [userBio, setUserBio] = useState('');
  const [comments, setComments] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(data => {
        setUserBio(data.bio);
        setComments(data.comments);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load user data:', err);
        setLoading(false);
      });
  }, [userId]);

  if (loading) return <div>Loading...</div>;

  return (
    <div style={{ padding: '20px', border: '1px solid #ccc', margin: '10px' }}>
      <h2>About {getUserName()}</h2>
      <p>{userBio}</p>
      
      <div>
        <h3>Comments:</h3>
        {comments.map(comment => (
          <div key={comment.id} style={{ margin: '10px 0', padding: '10px', backgroundColor: '#f5f5f5' }}>
            <strong>{comment.author}:</strong> {comment.text}
          </div>
        ))}
      </div>
      
      <div>
        Search results for: "{getSearchParam('query')}"
      </div>
      
      <div>
        Last search: "{getLastSearch()}"
      </div>
    </div>
  );
}

export function MessageBoard() {
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setMessages([...messages, { 
      id: Date.now(), 
      text: message,
      author: getCurrentUser(),
      timestamp: new Date().toLocaleString()
    }]);
    setMessage('');
  };

  return (
    <div style={{ padding: '20px', border: '1px solid #ddd', margin: '10px' }}>
      <h3>Message Board</h3>
      <form onSubmit={handleSubmit}>
        <textarea 
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your message..."
          style={{ width: '100%', height: '100px', margin: '10px 0' }}
        />
        <button type="submit" style={{ padding: '10px 20px' }}>Post Message</button>
      </form>

      <div>
        {messages.map(msg => (
          <div key={msg.id} style={{ margin: '10px 0', padding: '10px', backgroundColor: '#e8f4f8' }}>
            <strong>{msg.author}</strong> <em>({msg.timestamp}):</em><br />
            {msg.text}
          </div>
        ))}
      </div>
    </div>
  );
}

function getUserName() {
  if (typeof window !== 'undefined') {
    return new URLSearchParams(window.location.search).get('user') || 'Anonymous';
  }
  return 'Anonymous';
}

function getSearchParam(param) {
  if (typeof window !== 'undefined') {
    return new URLSearchParams(window.location.search).get(param) || '';
  }
  return '';
}

function getLastSearch() {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('lastSearch') || '';
  }
  return '';
}

function getCurrentUser() {
  return 'CurrentUser'; // Simplified for example
}

export default UserProfile;
