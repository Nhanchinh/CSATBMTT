export interface EncryptRequest {
    plaintext: string;
    key: string;
}

export interface DecryptRequest {
    ciphertext: string;
    key: string;
}

export interface EncryptResponse {
    ciphertext: string;
    key_length: number;
    encrypt_time_ms: number;
}

export interface DecryptResponse {
    plaintext: string;
    key_length: number;
    decrypt_time_ms: number;
}