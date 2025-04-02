import { useState, useRef } from 'react';
import axios from 'axios';
import { EncryptRequest, DecryptRequest, EncryptResponse, DecryptResponse } from './types/crypto';
import './App.css';

function App() {
  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [encryptionTime, setEncryptionTime] = useState<number | null>(null);
  const [decryptionTime, setDecryptionTime] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'text' | 'file'>('text');
  const [keyLength, setKeyLength] = useState(16);
  const [mode, setMode] = useState<'encrypt-decrypt' | 'decrypt-only'>('encrypt-decrypt');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const handleEncrypt = async () => {
    if (!secretKey) {
      alert('Vui lòng nhập khóa bí mật!');
      return;
    }

    if (secretKey.length !== keyLength) {
      alert(`Khóa bí mật phải có độ dài ${keyLength} ký tự cho AES-${keyLength * 8}!`);
      return;
    }

    setIsProcessing(true);
    const textToEncrypt = activeTab === 'text' ? inputText : fileContent;

    try {
      const request: EncryptRequest = { plaintext: textToEncrypt, key: secretKey };
      const response = await axios.post<EncryptResponse>(
        'http://localhost:8080/encrypt',
        request
      );
      setEncryptedText(response.data.ciphertext);
      setEncryptionTime(response.data.encrypt_time_ms);
      setDecryptedText('');
      setDecryptionTime(null);
    } catch (error) {
      alert('Lỗi khi mã hóa: ' + (error as Error).message);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDecrypt = async () => {
    if (!secretKey) {
      alert('Vui lòng nhập khóa bí mật!');
      return;
    }

    if (secretKey.length !== keyLength) {
      alert(`Khóa bí mật phải có độ dài ${keyLength} ký tự cho AES-${keyLength * 8}!`);
      return;
    }

    const textToDecrypt = mode === 'encrypt-decrypt' ? encryptedText : (activeTab === 'text' ? inputText : fileContent);
    if (!textToDecrypt) {
      alert('Không có dữ liệu mã hóa để giải mã!');
      return;
    }

    setIsProcessing(true);

    try {
      const request: DecryptRequest = { ciphertext: textToDecrypt, key: secretKey };
      const response = await axios.post<DecryptResponse>(
        'http://localhost:8080/decrypt',
        request
      );
      setDecryptedText(response.data.plaintext);
      setDecryptionTime(response.data.decrypt_time_ms);
      if (mode === 'decrypt-only') {
        setEncryptedText(textToDecrypt); // Hiển thị input đã mã hóa
      }
    } catch (error) {
      alert('Lỗi khi giải mã: ' + (error as Error).message);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();

    reader.onload = (event) => {
      setFileContent(event.target?.result as string);
    };

    reader.readAsText(file);
  };

  const handleDownload = (content: string, type: 'encrypted' | 'decrypted') => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download =
      type === 'encrypted'
        ? fileName
          ? `${fileName}.encrypted`
          : 'encrypted.txt'
        : fileName
          ? `${fileName}.decrypted`
          : 'decrypted.txt';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const clearAll = () => {
    setInputText('');
    setEncryptedText('');
    setDecryptedText('');
    setEncryptionTime(null);
    setDecryptionTime(null);
    setFileContent('');
    setFileName('');
    setSecretKey('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="container">
      <h1>Mã hóa và Giải mã AES</h1>

      <div className="mode-section">
        <label>Chế độ:</label>
        <select
          value={mode}
          onChange={(e) => {
            setMode(e.target.value as 'encrypt-decrypt' | 'decrypt-only');
            clearAll();
          }}
        >
          <option value="encrypt-decrypt">Mã hóa & Giải mã</option>
          <option value="decrypt-only">Chỉ giải mã</option>
        </select>
      </div>

      <div className="key-section">
        <label htmlFor="keyLength">Loại mã hóa:</label>
        <select
          id="keyLength"
          value={keyLength}
          onChange={(e) => {
            setKeyLength(Number(e.target.value));
            setSecretKey('');
          }}
        >
          <option value={16}>AES-128 (16 ký tự)</option>
          <option value={24}>AES-192 (24 ký tự)</option>
          <option value={32}>AES-256 (32 ký tự)</option>
        </select>
      </div>

      <div className="key-section">
        <label htmlFor="secretKey">Khóa bí mật ({keyLength} ký tự):</label>
        <input
          type="text"
          id="secretKey"
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          maxLength={keyLength}
          placeholder={`Nhập khóa ${keyLength} ký tự`}
        />
        <small>Lưu ý: Khóa phải đúng {keyLength} ký tự cho AES-{keyLength * 8}</small>
      </div>

      <div className="tabs">
        <button
          className={activeTab === 'text' ? 'active' : ''}
          onClick={() => setActiveTab('text')}
        >
          Văn bản
        </button>
        <button
          className={activeTab === 'file' ? 'active' : ''}
          onClick={() => setActiveTab('file')}
        >
          Tệp tin
        </button>
      </div>

      {activeTab === 'text' ? (
        <div className="text-input-section">
          <label htmlFor="inputText">
            {mode === 'encrypt-decrypt' ? 'Văn bản đầu vào:' : 'Văn bản đã mã hóa:'}
          </label>
          <textarea
            id="inputText"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder={mode === 'encrypt-decrypt' ? 'Nhập văn bản cần mã hóa' : 'Nhập văn bản đã mã hóa'}
            rows={5}
          />
        </div>
      ) : (
        <div className="file-input-section">
          <label htmlFor="fileInput">
            {mode === 'encrypt-decrypt' ? 'Chọn tệp tin:' : 'Chọn tệp đã mã hóa:'}
          </label>
          <input type="file" id="fileInput" ref={fileInputRef} onChange={handleFileChange} />
          {fileName && (
            <div className="file-info">
              <p>Tệp đã chọn: {fileName}</p>
              <p>Kích thước nội dung: {fileContent.length} ký tự</p>
            </div>
          )}
        </div>
      )}

      <div className="button-group">
        {mode === 'encrypt-decrypt' && (
          <button
            onClick={handleEncrypt}
            disabled={isProcessing || (!inputText && !fileContent) || !secretKey}
          >
            {isProcessing ? 'Đang mã hóa...' : 'Mã hóa'}
          </button>
        )}
        <button
          onClick={handleDecrypt}
          disabled={isProcessing || (mode === 'encrypt-decrypt' && !encryptedText) || (mode === 'decrypt-only' && !inputText && !fileContent) || !secretKey}
        >
          {isProcessing ? 'Đang giải mã...' : 'Giải mã'}
        </button>
        <button onClick={clearAll} disabled={isProcessing}>
          Xóa tất cả
        </button>
      </div>

      {encryptionTime !== null && mode === 'encrypt-decrypt' && (
        <div className="time-info">
          <p>Thời gian mã hóa: {encryptionTime.toFixed(2)} ms</p>
        </div>
      )}

      {encryptedText && (
        <div className="result-section">
          <h3>Kết quả mã hóa (AES-{keyLength * 8}):</h3>
          <textarea value={encryptedText} readOnly rows={5} />
          <button onClick={() => handleDownload(encryptedText, 'encrypted')}>
            Tải xuống văn bản mã hóa
          </button>
        </div>
      )}

      {decryptionTime !== null && (
        <div className="time-info">
          <p>Thời gian giải mã: {decryptionTime.toFixed(2)} ms</p>
        </div>
      )}

      {decryptedText && (
        <div className="result-section">
          <h3>Kết quả giải mã (AES-{keyLength * 8}):</h3>
          <textarea value={decryptedText} readOnly rows={5} />
          <button onClick={() => handleDownload(decryptedText, 'decrypted')}>
            Tải xuống văn bản giải mã
          </button>
        </div>
      )}
    </div>
  );
}

export default App;