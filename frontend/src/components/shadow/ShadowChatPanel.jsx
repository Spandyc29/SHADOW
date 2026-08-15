import React, { useState, useRef, useEffect } from 'react';
import api from '../../services/api';
import { useScanContext } from '../../context/ScanContext';
import { shadowStateController } from './ShadowStateController';
import { SHADOW_STATES } from './ShadowConstants';
import '../../styles/shadow-chat-panel.css';

export default function ShadowChatPanel({ isOpen, onClose }) {
  const { scanContext } = useScanContext();

  const [messages, setMessages] = useState([
    {
      id: 1,
      sender: 'ai',
      text: 'Greetings, operative. I am Shadow AI. How can I assist you with threat analysis today?',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const [inputVal, setInputVal] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom of messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isTyping, isOpen]);

  const handleSend = async (e) => {
    e?.preventDefault();
    const trimmed = inputVal.trim();
    if (!trimmed || isTyping) return;

    const userTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const userMsg = {
      id: Date.now(),
      sender: 'user',
      text: trimmed,
      time: userTime,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputVal('');
    setIsTyping(true);

    // Switch mascot widget to THINKING state
    shadowStateController.setState(SHADOW_STATES.THINKING, true);

    try {
      const response = await api.post('/api/shadow-ai/chat', {
        message: trimmed,
        scanContext: scanContext || null,
      });

      const aiReply = response.data?.reply || "Shadow AI is having trouble responding right now — please try again in a moment.";
      const aiTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 1,
          sender: 'ai',
          text: aiReply,
          time: aiTime,
        },
      ]);
    } catch (err) {
      console.error('Error calling Shadow AI backend:', err);
      const errTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      setMessages((prev) => [
        ...prev,
        {
          id: Date.now() + 1,
          sender: 'ai',
          text: "Shadow AI is having trouble responding right now — please try again in a moment.",
          time: errTime,
        },
      ]);
    } finally {
      setIsTyping(false);
      // Restore mascot widget to IDLE state
      shadowStateController.setState(SHADOW_STATES.IDLE, true);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className={`shadow-chat-panel-overlay ${isOpen ? 'is-open' : ''}`}>
      {/* Header */}
      <div className="shadow-chat-header">
        <div className="shadow-chat-brand">
          <div className="shadow-chat-avatar-mini">S</div>
          <div className="shadow-chat-title-group">
            <h3 className="shadow-chat-title">
              Shadow AI <span className="shadow-chat-online-dot" />
            </h3>
            <span className="shadow-chat-subtitle">
              {scanContext ? `Scan Context: ${scanContext.verdict}` : 'Threat Analysis Companion'}
            </span>
          </div>
        </div>
        <button
          className="shadow-chat-close-btn"
          onClick={onClose}
          aria-label="Close Chat Panel"
        >
          ✕
        </button>
      </div>

      {/* Mandatory Risk Engine Disclaimer Line */}
      <div className="shadow-chat-disclaimer">
        <span className="shadow-chat-disclaimer-icon">ℹ</span>
        <span>
          Shadow AI explains — it does not decide. Verdicts come from SHADOW's Risk Engine.
        </span>
      </div>

      {/* Scrollable Message List */}
      <div className="shadow-chat-messages-container">
        {messages.map((msg) => (
          <div key={msg.id} className={`shadow-message-row ${msg.sender}`}>
            <div className="shadow-message-bubble">{msg.text}</div>
            <span className="shadow-message-time">{msg.time}</span>
          </div>
        ))}

        {/* Typing Indicator */}
        {isTyping && (
          <div className="shadow-typing-indicator">
            <span className="shadow-typing-dot" />
            <span className="shadow-typing-dot" />
            <span className="shadow-typing-dot" />
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <form className="shadow-chat-input-area" onSubmit={handleSend}>
        <input
          type="text"
          className="shadow-chat-input"
          placeholder={scanContext ? "Ask Shadow AI about this scan..." : "Ask Shadow AI about threat analysis..."}
          value={inputVal}
          onChange={(e) => setInputVal(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isTyping}
        />
        <button
          type="submit"
          className="shadow-chat-send-btn"
          disabled={!inputVal.trim() || isTyping}
        >
          Send
        </button>
      </form>
    </div>
  );
}
