import React, { useState, useEffect } from 'react';
import { Copy, Sun, Moon, Clock } from 'lucide-react';

const JWTDecoder = () => {
  const [jwt, setJwt] = useState('');
  const [header, setHeader] = useState('');
  const [payload, setPayload] = useState('');
  const [signature, setSignature] = useState('');
  const [secret, setSecret] = useState('');
  const [validationState, setValidationState] = useState('invalid'); // invalid, unverified, verified
  const [darkMode, setDarkMode] = useState(true);
  const [timeRemaining, setTimeRemaining] = useState(null);
  const [copied, setCopied] = useState('');

  // Base64URL decode
  const base64UrlDecode = (str) => {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return decodeURIComponent(atob(base64).split('').map(c => 
      '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(''));
  };

  // Base64URL encode
  const base64UrlEncode = (str) => {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  // Decode JWT
  const decodeJWT = (token) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        setValidationState('invalid');
        return false;
      }

      const decodedHeader = base64UrlDecode(parts[0]);
      const decodedPayload = base64UrlDecode(parts[1]);
      
      const headerObj = JSON.parse(decodedHeader);
      const payloadObj = JSON.parse(decodedPayload);
      
      setHeader(JSON.stringify(headerObj, null, 2));
      setPayload(JSON.stringify(payloadObj, null, 2));
      setSignature(parts[2]);
      setValidationState('unverified');
      
      // Calculate time remaining if exp exists
      if (payloadObj.exp) {
        const now = Math.floor(Date.now() / 1000);
        const remaining = payloadObj.exp - now;
        setTimeRemaining(remaining > 0 ? remaining : 0);
      } else {
        setTimeRemaining(null);
      }
      
      return true;
    } catch (e) {
      setValidationState('invalid');
      setHeader('');
      setPayload('');
      setSignature('');
      setTimeRemaining(null);
      return false;
    }
  };

  // Encode JWT from parts
  const encodeJWT = async () => {
    try {
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(payload);
      
      const encodedHeader = base64UrlEncode(JSON.stringify(headerObj));
      const encodedPayload = base64UrlEncode(JSON.stringify(payloadObj));
      
      let newSignature = signature;
      
      // If secret is provided, generate signature
      if (secret && headerObj.alg) {
        const data = `${encodedHeader}.${encodedPayload}`;
        
        if (headerObj.alg === 'HS256') {
          // Generate HMAC SHA-256 signature
          const encoder = new TextEncoder();
          const keyData = encoder.encode(secret);
          const messageData = encoder.encode(data);
          
          const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
          );
          
          const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
          const signatureArray = Array.from(new Uint8Array(signatureBuffer));
          const signatureBase64 = btoa(String.fromCharCode(...signatureArray))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          
          newSignature = signatureBase64;
          setSignature(signatureBase64);
          setValidationState('verified');
        }
      }
      
      const newJwt = `${encodedHeader}.${encodedPayload}.${newSignature}`;
      setJwt(newJwt);
      
      if (!secret && newSignature) {
        setValidationState('unverified');
      }
    } catch (e) {
      console.error('Encoding error:', e);
    }
  };

  // Handle JWT input change
  useEffect(() => {
    if (jwt) {
      decodeJWT(jwt);
    } else {
      setHeader('');
      setPayload('');
      setSignature('');
      setValidationState('invalid');
      setTimeRemaining(null);
    }
  }, [jwt]);

  // Handle component edits
  useEffect(() => {
    if (header && payload) {
      encodeJWT();
    }
  }, [header, payload, secret]);

  // Countdown timer
  useEffect(() => {
    if (timeRemaining === null || timeRemaining <= 0) return;
    
    const timer = setInterval(() => {
      setTimeRemaining(prev => {
        if (prev <= 1) return 0;
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, [timeRemaining]);

  // Format time remaining
  const formatTime = (seconds) => {
    if (seconds <= 0) return 'Expired';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (days > 0) return `${days}d ${hours}h ${mins}m ${secs}s`;
    if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  // Copy to clipboard
  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(''), 2000);
  };

  // Get border color
  const getBorderColor = () => {
    if (validationState === 'invalid') return darkMode ? 'border-red-500' : 'border-red-500';
    if (validationState === 'unverified') return darkMode ? 'border-yellow-500' : 'border-yellow-500';
    return darkMode ? 'border-green-500' : 'border-green-500';
  };

  // Highlight special fields
  const highlightJSON = (jsonStr, type) => {
    if (!jsonStr) return '';
    
    try {
      const obj = JSON.parse(jsonStr);
      const highlighted = JSON.stringify(obj, null, 2);
      
      if (type === 'payload') {
        return highlighted
          .replace(/"(exp|iat|iss)":/g, '<span class="font-bold text-blue-500">\"$1\":</span>');
      }
      
      return highlighted;
    } catch {
      return jsonStr;
    }
  };

  // Get JWT part colors
  const getJWTColor = (part) => {
    if (validationState === 'invalid') return darkMode ? 'text-gray-400' : 'text-gray-500';
    
    const colors = {
      header: darkMode ? 'text-red-400' : 'text-red-600',
      payload: darkMode ? 'text-purple-400' : 'text-purple-600',
      signature: darkMode ? 'text-cyan-400' : 'text-cyan-600'
    };
    
    return colors[part];
  };

  return (
    <div className={`min-h-screen ${darkMode ? 'bg-gray-900 text-white' : 'bg-gray-50 text-gray-900'} transition-colors`}>
      {/* Header */}
      <div className="text-center py-8 px-4 border-b border-gray-300 dark:border-gray-700">
        <div className="flex justify-end max-w-7xl mx-auto mb-4">
          <button
            onClick={() => setDarkMode(!darkMode)}
            className={`p-2 rounded-lg ${darkMode ? 'bg-gray-800 hover:bg-gray-700' : 'bg-white hover:bg-gray-100'} transition-colors`}
          >
            {darkMode ? <Sun size={20} /> : <Moon size={20} />}
          </button>
        </div>
        <h1 className="text-4xl font-bold mb-2">JWT Decoder/Encoder</h1>
        <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
          Decode and encode JSON Web Tokens in real-time
        </p>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto p-4 md:p-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Side - JWT Input */}
          <div>
            <div className="mb-4 flex items-center justify-between">
              <label className="text-lg font-semibold">JWT Token</label>
              <button
                onClick={() => copyToClipboard(jwt, 'jwt')}
                className={`flex items-center gap-2 px-3 py-1 rounded ${
                  darkMode ? 'bg-gray-800 hover:bg-gray-700' : 'bg-white hover:bg-gray-100'
                } transition-colors text-sm`}
                disabled={!jwt}
              >
                <Copy size={16} />
                {copied === 'jwt' ? 'Copied!' : 'Copy'}
              </button>
            </div>
            
            <div className={`border-4 ${getBorderColor()} rounded-lg transition-colors`}>
              <textarea
                value={jwt}
                onChange={(e) => setJwt(e.target.value)}
                placeholder="Paste your JWT token here..."
                className={`w-full p-4 rounded-lg font-mono text-sm resize-none ${
                  darkMode ? 'bg-gray-800 text-white' : 'bg-white text-gray-900'
                } focus:outline-none`}
                rows={8}
                style={{ wordBreak: 'break-all' }}
              />
            </div>
            
            <div className="mt-4 flex items-center gap-4">
              <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                Status: <span className={`font-semibold ${
                  validationState === 'invalid' ? 'text-red-500' :
                  validationState === 'unverified' ? 'text-yellow-500' :
                  'text-green-500'
                }`}>
                  {validationState === 'invalid' ? 'Invalid JWT' :
                   validationState === 'unverified' ? 'Valid (Signature Not Verified)' :
                   'Valid & Verified'}
                </span>
              </div>
            </div>

            {timeRemaining !== null && (
              <div className={`mt-4 p-4 rounded-lg ${
                darkMode ? 'bg-gray-800' : 'bg-white'
              } border ${timeRemaining > 0 ? 'border-green-500' : 'border-red-500'}`}>
                <div className="flex items-center gap-2">
                  <Clock size={20} className={timeRemaining > 0 ? 'text-green-500' : 'text-red-500'} />
                  <span className="font-semibold">
                    {timeRemaining > 0 ? 'Expires in:' : 'Token expired'}
                  </span>
                  <span className={`ml-auto font-mono ${timeRemaining > 0 ? 'text-green-500' : 'text-red-500'}`}>
                    {formatTime(timeRemaining)}
                  </span>
                </div>
              </div>
            )}

            {validationState !== 'invalid' && jwt && (
              <div className="mt-4 p-4 rounded-lg border border-gray-300 dark:border-gray-700 font-mono text-xs overflow-x-auto">
                <div className="break-all">
                  <span className={getJWTColor('header')}>{jwt.split('.')[0]}</span>
                  <span className={darkMode ? 'text-gray-500' : 'text-gray-400'}>.</span>
                  <span className={getJWTColor('payload')}>{jwt.split('.')[1]}</span>
                  <span className={darkMode ? 'text-gray-500' : 'text-gray-400'}>.</span>
                  <span className={getJWTColor('signature')}>{jwt.split('.')[2]}</span>
                </div>
              </div>
            )}
          </div>

          {/* Right Side - Decoded Parts */}
          <div className="space-y-6">
            {/* Header */}
            <div>
              <div className="mb-2 flex items-center justify-between">
                <label className="text-lg font-semibold text-red-500">Header</label>
                <button
                  onClick={() => copyToClipboard(header, 'header')}
                  className={`flex items-center gap-2 px-3 py-1 rounded ${
                    darkMode ? 'bg-gray-800 hover:bg-gray-700' : 'bg-white hover:bg-gray-100'
                  } transition-colors text-sm`}
                  disabled={!header}
                >
                  <Copy size={16} />
                  {copied === 'header' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <textarea
                value={header}
                onChange={(e) => setHeader(e.target.value)}
                placeholder='{"alg": "HS256", "typ": "JWT"}'
                className={`w-full p-4 rounded-lg font-mono text-sm resize-none border ${
                  darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'
                } focus:outline-none focus:border-red-500`}
                rows={4}
              />
            </div>

            {/* Payload */}
            <div>
              <div className="mb-2 flex items-center justify-between">
                <label className="text-lg font-semibold text-purple-500">Payload</label>
                <button
                  onClick={() => copyToClipboard(payload, 'payload')}
                  className={`flex items-center gap-2 px-3 py-1 rounded ${
                    darkMode ? 'bg-gray-800 hover:bg-gray-700' : 'bg-white hover:bg-gray-100'
                  } transition-colors text-sm`}
                  disabled={!payload}
                >
                  <Copy size={16} />
                  {copied === 'payload' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <textarea
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                placeholder='{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}'
                className={`w-full p-4 rounded-lg font-mono text-sm resize-none border ${
                  darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'
                } focus:outline-none focus:border-purple-500`}
                rows={8}
              />
            </div>

            {/* Secret */}
            <div>
              <div className="mb-2 flex items-center justify-between">
                <label className="text-lg font-semibold text-cyan-500">Secret Key</label>
                <button
                  onClick={() => copyToClipboard(secret, 'secret')}
                  className={`flex items-center gap-2 px-3 py-1 rounded ${
                    darkMode ? 'bg-gray-800 hover:bg-gray-700' : 'bg-white hover:bg-gray-100'
                  } transition-colors text-sm`}
                  disabled={!secret}
                >
                  <Copy size={16} />
                  {copied === 'secret' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <input
                type="text"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="Enter secret key to verify/sign JWT"
                className={`w-full p-4 rounded-lg font-mono text-sm border ${
                  darkMode ? 'bg-gray-800 text-white border-gray-700' : 'bg-white text-gray-900 border-gray-300'
                } focus:outline-none focus:border-cyan-500`}
              />
              {/* {secret && signature && (
                <div className={`mt-2 text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  <div className="font-semibold mb-1">Generated Signature:</div>
                  <div className="p-2 rounded bg-gray-100 dark:bg-gray-800 font-mono break-all">
                    {signature}
                  </div>
                </div>
              )} */}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default JWTDecoder;