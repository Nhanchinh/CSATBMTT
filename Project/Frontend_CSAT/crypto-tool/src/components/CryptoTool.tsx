import { useState } from 'react';
import axios from 'axios';
import { EncryptRequest, DecryptRequest, EncryptResponse, DecryptResponse } from '../types/crypto';
import './CryptoTool.css';

const CryptoTool: React.FC = () => {
    const [inputText, setInputText] = useState('');
    const [key, setKey] = useState('MySecretKey12345');
    const [output, setOutput] = useState('');
    const [isEncrypting, setIsEncrypting] = useState(true);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleEncrypt = async () => {
        setLoading(true);
        setError('');
        try {
            const request: EncryptRequest = { plaintext: inputText, key };
            const response = await axios.post<EncryptResponse>(
                'http://localhost:8080/encrypt',
                request
            );
            setOutput(response.data.ciphertext);
        } catch (err) {
            setError('Lỗi khi mã hóa: ' + (err as Error).message);
        } finally {
            setLoading(false);
        }
    };

    const handleDecrypt = async () => {
        setLoading(true);
        setError('');
        try {
            const request: DecryptRequest = { ciphertext: inputText, key };
            const response = await axios.post<DecryptResponse>(
                'http://localhost:8080/decrypt',
                request
            );
            setOutput(response.data.plaintext);
        } catch (err) {
            setError('Lỗi khi giải mã: ' + (err as Error).message);
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (isEncrypting) handleEncrypt();
        else handleDecrypt();
    };

    return (
        <div className="crypto-container">
            <h1>Công cụ Mã hóa/Giải mã</h1>

            <form onSubmit={handleSubmit}>
                <div className="mode-toggle">
                    <label>
                        <input
                            type="radio"
                            checked={isEncrypting}
                            onChange={() => setIsEncrypting(true)}
                        />
                        Mã hóa
                    </label>
                    <label>
                        <input
                            type="radio"
                            checked={!isEncrypting}
                            onChange={() => setIsEncrypting(false)}
                        />
                        Giải mã
                    </label>
                </div>

                <div className="input-group">
                    <label>Khóa (Key):</label>
                    <input
                        type="text"
                        value={key}
                        onChange={(e) => setKey(e.target.value)}
                        placeholder="Nhập khóa bí mật"
                    />
                </div>

                <div className="input-group">
                    <label>{isEncrypting ? 'Văn bản gốc' : 'Văn bản mã hóa'}:</label>
                    <textarea
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                        placeholder={isEncrypting
                            ? 'Nhập văn bản cần mã hóa'
                            : 'Nhập văn bản mã hóa cần giải mã'}
                    />
                </div>

                <button type="submit" disabled={loading}>
                    {loading ? 'Đang xử lý...' : (isEncrypting ? 'Mã hóa' : 'Giải mã')}
                </button>

                {error && <div className="error">{error}</div>}

                {output && (
                    <div className="output-group">
                        <label>Kết quả:</label>
                        <textarea value={output} readOnly />
                        <button
                            type="button"
                            onClick={() => navigator.clipboard.writeText(output)}
                        >
                            Sao chép
                        </button>
                    </div>
                )}
            </form>
        </div>
    );
};

export default CryptoTool;