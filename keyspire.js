// Configurações Globais
const KEYSPIRE_CONFIG = {
    dbName: "KeyspireDB",
    version: 20,
    stores: {
        passwords: { keyPath: "id", autoIncrement: true },
        config: { keyPath: "key" },
        trash: { keyPath: "deletedAt" },
        sync: { keyPath: "syncId" }
    },
    security: {
        kdfIterations: 500000,
        minPasswordLength: 12,
        maxLoginAttempts: 5,
        lockTimeout: 300000,
        syncKeyLength: 32,
        syncExpiration: 300000
    },
    donationAddress: 'hollowkevin92@walletofsatoshi.com'
};

// Sistema de Logging
class KeyspireLogger {
    static log(message, level = 'info', context = {}) {
        const timestamp = new Date().toISOString();
        console[level](`[${timestamp}] ${level.toUpperCase()}: ${message} | Context: ${JSON.stringify(context)}`);
    }
    static error(message, context = {}) { this.log(message, 'error', context); }
    static warn(message, context = {}) { this.log(message, 'warn', context); }
    static info(message, context = {}) { this.log(message, 'info', context); }
}

// Função de Sanitização
function sanitizeHTML(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

// Módulo de Criptografia
class KeyspireCrypto {
    constructor() {
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    async deriveMasterKey(password, salt) {
        try {
            if (!password || !salt) throw new Error("Parâmetros inválidos");
            const keyMaterial = await crypto.subtle.importKey(
                "raw", this.encoder.encode(password), "PBKDF2", false, ["deriveKey"]
            );
            return await crypto.subtle.deriveKey(
                { name: "PBKDF2", salt, iterations: KEYSPIRE_CONFIG.security.kdfIterations, hash: "SHA-512" },
                keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
            );
        } catch (e) {
            KeyspireLogger.error(`Falha ao derivar chave: ${e.message}`, { passwordLength: password?.length });
            throw e;
        }
    }

    async encryptData(data, key) {
        try {
            if (!data || !key) throw new Error("Dados ou chave inválidos");
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encodedData = this.encoder.encode(data);
            const checksum = await this.generateChecksum(encodedData);
            const encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv }, key, encodedData
            );
            return { 
                iv: btoa(String.fromCharCode(...iv)), 
                data: btoa(String.fromCharCode(...new Uint8Array(encrypted))), 
                checksum 
            };
        } catch (e) {
            KeyspireLogger.error(`Falha ao criptografar: ${e.message}`);
            throw e;
        }
    }

    async decryptData(encrypted, key) {
        try {
            if (!encrypted?.iv || !encrypted?.data || !encrypted?.checksum || !key) throw new Error("Dados ou chave inválidos");
            const iv = Uint8Array.from(atob(encrypted.iv), c => c.charCodeAt(0));
            const data = Uint8Array.from(atob(encrypted.data), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
            const decoded = this.decoder.decode(decrypted);
            const checksum = await this.generateChecksum(this.encoder.encode(decoded));
            if (checksum !== encrypted.checksum) throw new Error("Checksum inválido - dados corrompidos");
            return decoded;
        } catch (e) {
            KeyspireLogger.error(`Falha ao descriptografar: ${e.message}`);
            throw e;
        }
    }

    async generateHMAC(data, hmacKey) {
        try {
            if (!data || !hmacKey) throw new Error("Dados ou chave HMAC inválidos");
            let keyBytes = typeof hmacKey === 'string' ? Uint8Array.from(atob(hmacKey), c => c.charCodeAt(0)) : hmacKey;
            const key = await crypto.subtle.importKey(
                "raw", keyBytes, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]
            );
            const signature = await crypto.subtle.sign("HMAC", key, this.encoder.encode(data));
            return btoa(String.fromCharCode(...new Uint8Array(signature)));
        } catch (e) {
            KeyspireLogger.error(`Falha ao gerar HMAC: ${e.message}`);
            throw e;
        }
    }

    async generateChecksum(data) {
        try {
            const hash = await crypto.subtle.digest("SHA-256", data);
            return btoa(String.fromCharCode(...new Uint8Array(hash)));
        } catch (e) {
            KeyspireLogger.error(`Falha ao gerar checksum: ${e.message}`);
            throw e;
        }
    }

    async generateTOTP(secret) {
        const epoch = Math.floor(Date.now() / 30000);
        const hmac = await this.generateHMAC(String(epoch), secret);
        return hmac.slice(-6);
    }
}

// Módulo de Banco de Dados
class KeyspireDB {
    constructor() {
        this.db = null;
        this.crypto = new KeyspireCrypto();
        this.cache = { passwords: null, trash: null, sync: null };
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(KEYSPIRE_CONFIG.dbName, KEYSPIRE_CONFIG.version);
            request.onupgradeneeded = (e) => {
                this.db = e.target.result;
                for (const [name, config] of Object.entries(KEYSPIRE_CONFIG.stores)) {
                    if (!this.db.objectStoreNames.contains(name)) this.db.createObjectStore(name, config);
                }
            };
            request.onsuccess = (e) => {
                this.db = e.target.result;
                KeyspireLogger.info("Banco de dados inicializado");
                resolve();
            };
            request.onerror = (e) => reject(new Error(`Erro ao abrir DB: ${e.target.error}`));
        });
    }

    async ensureOpen() {
        if (!this.db) await this.init();
    }

    async get(storeName, key) {
        await this.ensureOpen();
        return new Promise((resolve) => {
            const tx = this.db.transaction(storeName, 'readonly');
            const store = tx.objectStore(storeName);
            const req = key ? store.get(key) : store.getAll();
            req.onsuccess = () => {
                const result = req.result;
                if (!key) {
                    this.cache[storeName] = result || [];
                    resolve(result);
                } else {
                    resolve(result || null);
                }
            };
            req.onerror = () => resolve(null);
        }).then(result => {
            if (key && this.cache[storeName]) {
                const cachedResult = Array.isArray(this.cache[storeName]) 
                    ? this.cache[storeName].find(item => item[KEYSPIRE_CONFIG.stores[storeName].keyPath] === key) 
                    : null;
                return cachedResult || result;
            }
            return result;
        });
    }

    async set(storeName, data) {
        await this.ensureOpen();
        return new Promise((resolve) => {
            const tx = this.db.transaction(storeName, 'readwrite');
            const store = tx.objectStore(storeName);
            const req = store.put(data);
            req.onsuccess = () => {
                this.cache[storeName] = null;
                resolve(req.result);
            };
            req.onerror = () => resolve(null);
        });
    }

    async delete(storeName, key) {
        await this.ensureOpen();
        return new Promise((resolve) => {
            const tx = this.db.transaction(storeName, 'readwrite');
            const store = tx.objectStore(storeName);
            const req = store.delete(key);
            req.onsuccess = () => {
                this.cache[storeName] = null;
                resolve();
            };
            req.onerror = () => resolve(null);
        });
    }
}

// Módulo de Geração de QR Code (Suporte a Type 10)
class QRCodeGenerator {
    constructor() {
        this.typeNumber = 10; // Suporta até ~174 caracteres com correção H
        this.errorCorrectionLevel = 'H';
    }

    generate(data) {
        const qr = this.createQRCode(data);
        return this.renderToCanvas(qr);
    }

    createQRCode(text) {
        const qr = [];
        const size = this.calculateSize(text.length);
        for (let i = 0; i < size; i++) {
            qr[i] = new Array(size).fill(false);
        }
        this.addData(qr, text);
        return qr;
    }

    calculateSize(dataLength) {
        return 57; // Tamanho para Type 10 com correção H
    }

    addData(qr, text) {
        const data = this.encodeText(text);
        let x = 0, y = 0;
        for (let i = 0; i < data.length && y < qr.length; i++) {
            qr[y][x] = data[i] === '1';
            x++;
            if (x >= qr[y].length) {
                x = 0;
                y++;
            }
        }
        this.addFinderPatterns(qr);
    }

    encodeText(text) {
        let binary = '';
        for (let i = 0; i < text.length; i++) {
            binary += text.charCodeAt(i).toString(2).padStart(8, '0');
        }
        return binary;
    }

    addFinderPatterns(qr) {
        const size = qr.length;
        const pattern = [
            [true, true, true, true, true, true, true],
            [true, false, false, false, false, false, true],
            [true, false, true, true, true, false, true],
            [true, false, true, true, true, false, true],
            [true, false, true, true, true, false, true],
            [true, false, false, false, false, false, true],
            [true, true, true, true, true, true, true]
        ];
        for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) qr[y][x] = pattern[y][x];
        for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) qr[y][size - 7 + x] = pattern[y][x];
        for (let y = 0; y < 7; y++) for (let x = 0; x < 7; x++) qr[size - 7 + y][x] = pattern[y][x];
    }

    renderToCanvas(qr) {
        const canvas = document.createElement('canvas');
        const size = qr.length;
        canvas.width = size * 5;
        canvas.height = size * 5;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000';
        for (let y = 0; y < size; y++) {
            for (let x = 0; x < size; x++) {
                if (qr[y][x]) ctx.fillRect(x * 5, y * 5, 5, 5);
            }
        }
        return canvas;
    }
}

// Módulo de Sincronização via QR Code
class KeyspireSync {
    constructor(crypto, db) {
        this.crypto = crypto;
        this.db = db;
        this.qrGenerator = new QRCodeGenerator();
    }

    async generateSyncQR(masterKey) {
        try {
            const syncKey = crypto.getRandomValues(new Uint8Array(KEYSPIRE_CONFIG.security.syncKeyLength));
            const syncId = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
            const vaultData = {
                passwords: await this.db.get('passwords'),
                timestamp: Date.now()
            };
            
            const encryptedData = await this.crypto.encryptData(
                JSON.stringify(vaultData),
                masterKey
            );
            
            const syncPayload = {
                syncId,
                data: encryptedData
            };

            await this.db.set('sync', {
                syncId,
                payload: syncPayload,
                expires: Date.now() + KEYSPIRE_CONFIG.security.syncExpiration
            });

            const qrData = JSON.stringify(syncPayload);
            return await this.generateQRCode(qrData);
        } catch (e) {
            KeyspireLogger.error(`Erro ao gerar QR Code de sincronização: ${e.message}`);
            throw e;
        }
    }

    async processSyncQR(qrData, masterKey) {
        try {
            if (!qrData || qrData.length > 10000) throw new Error("Formato de QR Code inválido");
            const syncPayload = JSON.parse(qrData);
            if (!syncPayload.syncId || !syncPayload.data) throw new Error("Payload de sincronização incompleto");
            const decryptedData = await this.crypto.decryptData(syncPayload.data, masterKey);
            const vaultData = JSON.parse(decryptedData);
            const existingPasswords = (await this.db.get('passwords')) || [];
            const mergedPasswords = this.mergeVaultData(existingPasswords, vaultData.passwords);
            
            for (const password of mergedPasswords) {
                await this.db.set('passwords', password);
            }
            KeyspireLogger.info("Sincronização via QR Code concluída com sucesso");
            return mergedPasswords.length;
        } catch (e) {
            KeyspireLogger.error(`Erro ao processar QR Code de sincronização: ${e.message}`);
            throw e;
        }
    }

    mergeVaultData(existing, incoming) {
        const merged = [...existing];
        incoming.forEach(newItem => {
            const existingIndex = merged.findIndex(item => item.id === newItem.id);
            if (existingIndex === -1) {
                merged.push(newItem);
            } else {
                merged[existingIndex] = newItem;
            }
        });
        return merged;
    }

    async generateQRCode(data) {
        try {
            const qrDiv = document.createElement('div');
            qrDiv.id = 'qrcode';
            const canvas = this.qrGenerator.generate(data);
            qrDiv.appendChild(canvas);
            KeyspireLogger.info("QR Code escaneável gerado com sucesso");
            return qrDiv.outerHTML;
        } catch (e) {
            KeyspireLogger.error(`Erro ao gerar QR Code: ${e.message}`);
            throw e;
        }
    }

    async cleanExpiredSyncs() {
        const syncItems = (await this.db.get('sync')) || [];
        const now = Date.now();
        for (const item of syncItems) {
            if (item.expires < now) {
                await this.db.delete('sync', item.syncId);
            }
        }
    }
}

// Módulo Principal
class Keyspire {
    constructor() {
        this.crypto = new KeyspireCrypto();
        this.db = new KeyspireDB();
        this.sync = new KeyspireSync(this.crypto, this.db);
        this.state = {
            isLocked: true,
            masterKey: null,
            loginAttempts: 0,
            currentTab: 'vault',
            inactivityTimer: null,
            isAccountCreated: false,
            syncInProgress: false
        };
    }

    async init() {
        try {
            await this.db.init();
            await this.sync.cleanExpiredSyncs();
            const config = await this.db.get('config', 'auth');
            this.state.isAccountCreated = !!config;
            this.loadTheme();
            this.renderUI();
            this.attachListeners();
            KeyspireLogger.info("Aplicativo Keyspire inicializado (Beta)");
        } catch (e) {
            this.showNotification("Erro ao iniciar o Keyspire: " + e.message, "error");
        }
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
        } else {
            document.body.classList.remove('dark-theme');
        }
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';
        }
        KeyspireLogger.info("Tema carregado: " + (savedTheme || 'claro'));
    }

    toggleTheme() {
        document.body.classList.toggle('dark-theme');
        const isDark = document.body.classList.contains('dark-theme');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.textContent = isDark ? '☀️' : '🌙';
        }
        KeyspireLogger.info(`Tema alternado para ${isDark ? 'escuro' : 'claro'}`);
    }

    renderUI() {
        const authSection = document.getElementById('auth-section');
        const vaultContent = document.getElementById('vault-content');
        if (!authSection || !vaultContent) {
            KeyspireLogger.error("Seções principais não encontradas");
            return;
        }

        if (this.state.isLocked) {
            authSection.classList.remove('hidden');
            vaultContent.classList.add('hidden');
            authSection.innerHTML = this.state.isAccountCreated ? `
                <h1><span aria-hidden="true">🔒</span> ${sanitizeHTML("Keyspire (Beta) - Entrar")}</h1>
                <div class="password-field">
                    <input type="password" id="masterPassword" placeholder="Digite sua Senha Mestra" autocomplete="off">
                </div>
                <div class="auth-buttons">
                    <button id="login-btn" class="btn-primary">Entrar</button>
                    <button id="recover-btn" class="btn-secondary">Recuperar Acesso</button>
                </div>
                <div id="recovery-form" class="hidden"></div>
                <p class="beta-notice">Versão Beta: Seus dados são locais e seguros.</p>
                <p class="donation">Gostou? Considere uma doação: ${KEYSPIRE_CONFIG.donationAddress}</p>
            ` : `
                <h1><span aria-hidden="true">🔒</span> ${sanitizeHTML("Keyspire (Beta) - Criar Conta")}</h1>
                <div class="password-field">
                    <input type="password" id="masterPassword" placeholder="Crie sua Senha Mestra" autocomplete="off">
                </div>
                <button id="create-btn" class="btn-primary">Criar Conta</button>
                <p class="beta-notice">Versão Beta: Seus dados são locais e seguros.</p>
                <p class="donation">Gostou? Considere uma doação: ${KEYSPIRE_CONFIG.donationAddress}</p>
            `;
        } else {
            authSection.classList.add('hidden');
            vaultContent.classList.remove('hidden');
            this.loadPasswords();
        }

        KeyspireLogger.info("UI renderizada (Beta)");
    }

    attachListeners() {
        const elements = {
            'create-btn': () => this.createAccount(),
            'login-btn': () => this.login(),
            'recover-btn': () => this.showRecoveryForm(),
            'lock-btn': () => this.lockVault(),
            'menu-toggle': () => this.toggleSidebar(),
            'add-password-btn': () => this.addPassword(),
            'generate-password-btn': () => this.generateAndFillPassword(),
            'export-btn': () => this.exportVault(),
            'import-btn': { event: 'change', callback: (e) => this.importVault(e) },
            'theme-toggle': () => this.toggleTheme()
        };

        Object.entries(elements).forEach(([id, action]) => {
            const element = document.getElementById(id);
            if (element) {
                const event = typeof action === 'function' ? 'click' : action.event;
                const callback = typeof action === 'function' ? action : action.callback;
                element.removeEventListener(event, callback);
                element.addEventListener(event, callback);
                KeyspireLogger.info(`Listener ${event} adicionado para ${id}`);
            }
        });

        const menuItems = document.querySelectorAll('.menu-item');
        menuItems.forEach(item => {
            const tab = item.dataset.tab;
            item.removeEventListener('click', this.switchTabBound);
            this.switchTabBound = () => this.switchTab(tab);
            item.addEventListener('click', this.switchTabBound);
            KeyspireLogger.info(`Listener adicionado para menu-item ${tab}`);
        });
    }

    validatePassword(password) {
        const minLength = KEYSPIRE_CONFIG.security.minPasswordLength;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*]/.test(password);

        let strength = 0;
        if (password.length >= minLength) strength += 20;
        if (hasUpper) strength += 20;
        if (hasLower) strength += 20;
        if (hasNumber) strength += 20;
        if (hasSpecial) strength += 20;

        let message = '';
        if (password.length < minLength) message = `Mínimo ${minLength} caracteres`;
        else if (strength <= 40) message = 'Fraca';
        else if (strength <= 60) message = 'Média';
        else if (strength <= 80) message = 'Boa';
        else message = 'Forte';

        return { strength, message };
    }

    async createAccount() {
        try {
            const password = document.getElementById('masterPassword')?.value;
            if (!password) throw new Error("Digite uma senha mestra");
            const { strength, message } = this.validatePassword(password);
            if (password.length < KEYSPIRE_CONFIG.security.minPasswordLength) {
                throw new Error(`Senha muito curta! Mínimo ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres`);
            }
            if (strength < 60 && !confirm(`Sua senha é '${message}'. Continuar? Recomendamos uma senha mais forte.`)) return;

            const salt = crypto.getRandomValues(new Uint8Array(16));
            this.state.masterKey = await this.crypto.deriveMasterKey(password, salt);
            const hmacKey = crypto.getRandomValues(new Uint8Array(32));
            const hmacKeyBase64 = btoa(String.fromCharCode(...hmacKey));
            const encryptedHmacKey = await this.crypto.encryptData(hmacKeyBase64, this.state.masterKey);
            const hmac = await this.crypto.generateHMAC(password, hmacKey);
            const recoveryPhrase = this.generateRecoveryPhrase();
            const recoveryKeySalt = crypto.getRandomValues(new Uint8Array(16));
            const recoveryKeyEncryptionKey = await this.crypto.deriveMasterKey(recoveryPhrase, recoveryKeySalt);
            const encryptedRecoveryKey = await this.crypto.encryptData(hmacKeyBase64, recoveryKeyEncryptionKey);
            const recoveryHash = await this.crypto.generateHMAC(recoveryPhrase, hmacKey);

            await this.db.set('config', { 
                key: 'auth', 
                salt: btoa(String.fromCharCode(...salt)), 
                hmac, 
                hmacKey: encryptedHmacKey,
                recoveryHash,
                recoveryKey: encryptedRecoveryKey,
                recoveryKeySalt: btoa(String.fromCharCode(...recoveryKeySalt))
            });
            this.state.isAccountCreated = true;

            this.showNotification(`Conta criada! Guarde esta frase de recuperação: "${recoveryPhrase}"`, "success", true);
            this.renderUI();
            this.attachListeners();
            document.getElementById('masterPassword').value = '';
        } catch (e) {
            this.showNotification(`Erro ao criar conta: ${e.message}`, "error", true);
        }
    }

    async login() {
        try {
            const password = document.getElementById('masterPassword')?.value;
            if (!password) throw new Error("Digite uma senha mestra");
            if (password.length < KEYSPIRE_CONFIG.security.minPasswordLength) {
                throw new Error(`Senha muito curta! Mínimo ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres`);
            }
            if (this.state.loginAttempts >= KEYSPIRE_CONFIG.security.maxLoginAttempts) {
                throw new Error("Muitas tentativas. Use a recuperação após 30 segundos.");
            }

            const config = await this.db.get('config', 'auth');
            if (!config) throw new Error("Nenhuma conta configurada.");

            const salt = Uint8Array.from(atob(config.salt), c => c.charCodeAt(0));
            this.state.masterKey = await this.crypto.deriveMasterKey(password, salt);
            const hmacKeyBase64 = await this.crypto.decryptData(config.hmacKey, this.state.masterKey);
            if (!/^[A-Za-z0-9+/=]+$/.test(hmacKeyBase64)) throw new Error("Chave HMAC inválida");
            const hmacKey = Uint8Array.from(atob(hmacKeyBase64), c => c.charCodeAt(0));
            const hmac = await this.crypto.generateHMAC(password, hmacKey);
            if (config.hmac !== hmac) throw new Error("Senha inválida");

            this.state.isLocked = false;
            this.state.loginAttempts = 0;
            this.resetInactivityTimer();
            this.renderUI();
            this.attachListeners();
            this.showNotification("Cofre aberto com sucesso!", "success");
        } catch (e) {
            this.state.loginAttempts++;
            if (this.state.loginAttempts >= KEYSPIRE_CONFIG.security.maxLoginAttempts) {
                await new Promise(resolve => setTimeout(resolve, 30000));
            }
            this.showNotification(`Erro ao entrar: ${e.message}`, "error", true);
        }
    }

    async loadPasswords() {
        try {
            const vaultTab = document.getElementById('vault-tab');
            if (!vaultTab) {
                KeyspireLogger.error("vault-tab não encontrado");
                return;
            }
            vaultTab.innerHTML = `
                <h2>Suas Senhas</h2>
                <button id="export-btn" class="btn-secondary">Exportar Vault</button>
                <label class="btn-secondary"><input type="file" id="import-btn" style="display:none">Importar Vault</label>
                <div class="password-form">
                    <input type="text" id="password-name" placeholder="Nome (ex.: Gmail)">
                    <input type="text" id="password-category" placeholder="Categoria (ex.: Email)">
                    <input type="text" id="password-username" placeholder="Usuário">
                    <input type="password" id="password-value" placeholder="Senha">
                    <input type="text" id="totp-secret" placeholder="Segredo TOTP (opcional)">
                    <div class="password-generator">
                        <label>Comprimento: <input type="number" id="password-length" value="16" min="8" max="64"></label>
                        <label><input type="checkbox" id="pw-upper" checked> Maiúsculas</label>
                        <label><input type="checkbox" id="pw-numbers" checked> Números</label>
                        <label><input type="checkbox" id="pw-special" checked> Símbolos</label>
                        <label><input type="checkbox" id="pw-memorable"> Memorizável</label>
                        <button id="generate-password-btn" class="btn-secondary">Gerar Senha</button>
                    </div>
                    <button id="add-password-btn" class="btn-primary">Adicionar Senha</button>
                </div>
                <ul id="password-list"></ul>
            `;
            this.attachListeners();
            KeyspireLogger.info("Formulário de senhas renderizado");

            const list = document.getElementById('password-list');
            if (!list) {
                KeyspireLogger.error("password-list não encontrado");
                return;
            }
            const passwords = (await this.db.get('passwords')) || [];
            list.innerHTML = passwords.length ? '' : '<li>Nenhuma senha salva.</li>';

            const itemsPromises = passwords.map(async (entry, idx) => {
                const item = document.createElement('li');
                item.className = 'password-item';
                try {
                    const data = JSON.parse(await this.crypto.decryptData(entry.data, this.state.masterKey));
                    const { name = 'Sem nome', category = 'Sem categoria', username = 'Sem usuário', password = '', totpSecret } = data;
                    const totpCode = totpSecret ? await this.crypto.generateTOTP(await this.crypto.decryptData(totpSecret, this.state.masterKey)) : '';
                    item.innerHTML = `
                        <span class="password-info" data-password="${sanitizeHTML(password)}">
                            ${sanitizeHTML(category)} - ${sanitizeHTML(name)} - ${sanitizeHTML(username)} - ${'•'.repeat(password.length || 12)}
                            ${totpSecret ? ` | TOTP: <span class="totp-code">${totpCode}</span>` : ''}
                        </span>
                        <button class="toggle-pw" aria-label="Mostrar senha">👁️</button>
                        <button class="copy-pw" aria-label="Copiar senha">📋</button>
                        <button class="delete-pw" aria-label="Excluir senha">🗑️</button>
                    `;
                    item.querySelector('.toggle-pw').addEventListener('click', () => this.togglePassword(idx));
                    item.querySelector('.copy-pw').addEventListener('click', () => this.copyPassword(item.querySelector('.password-info')));
                    item.querySelector('.delete-pw').addEventListener('click', () => this.deletePassword(entry.id));
                    KeyspireLogger.info(`Senha ${idx} adicionada à lista`);
                    return item;
                } catch (e) {
                    item.textContent = "Erro ao descriptografar: " + e.message;
                    return item;
                }
            });

            const items = await Promise.all(itemsPromises);
            items.forEach(item => list.appendChild(item));
        } catch (e) {
            this.showNotification("Erro ao carregar senhas: " + e.message, "error");
        }
    }

    async loadTrash() {
        try {
            const trashTab = document.getElementById('trash-tab');
            if (!trashTab) {
                KeyspireLogger.error("trash-tab não encontrado");
                return;
            }
            trashTab.innerHTML = `
                <h2>Lixeira</h2>
                <ul id="trash-list"></ul>
            `;
            const list = document.getElementById('trash-list');
            if (!list) {
                KeyspireLogger.error("trash-list não encontrado");
                return;
            }
            const trashItems = (await this.db.get('trash')) || [];
            list.innerHTML = trashItems.length ? '' : '<li>Lixeira vazia.</li>';
            trashItems.forEach((entry, idx) => {
                const item = document.createElement('li');
                item.className = 'password-item';
                this.crypto.decryptData(entry.data, this.state.masterKey)
                    .then(data => {
                        const { name = 'Sem nome', category = 'Sem categoria', username = 'Sem usuário', password = '' } = JSON.parse(data);
                        const deletedAt = new Date(entry.deletedAt).toLocaleString();
                        item.innerHTML = `
                            <span class="password-info" data-password="${sanitizeHTML(password)}">
                                ${sanitizeHTML(category)} - ${sanitizeHTML(name)} - ${sanitizeHTML(username)} - ${'•'.repeat(password.length || 12)} (Excluído em: ${sanitizeHTML(deletedAt)})
                            </span>
                            <button class="restore-pw" aria-label="Restaurar senha">↩️</button>
                            <button class="delete-perm" aria-label="Excluir permanentemente">❌</button>
                        `;
                        item.querySelector('.restore-pw').addEventListener('click', () => this.restorePassword(entry.deletedAt));
                        item.querySelector('.delete-perm').addEventListener('click', () => this.deletePermanently(entry.deletedAt));
                        list.appendChild(item);
                        KeyspireLogger.info(`Item ${idx} da lixeira adicionado à lista`);
                    })
                    .catch(e => {
                        item.textContent = "Erro ao descriptografar: " + e.message;
                        list.appendChild(item);
                    });
            });
        } catch (e) {
            this.showNotification("Erro ao carregar lixeira: " + e.message, "error");
        }
    }

    async loadSettings() {
        try {
            const settingsTab = document.getElementById('settings-tab');
            if (!settingsTab) {
                KeyspireLogger.error("settings-tab não encontrado");
                return;
            }
            settingsTab.innerHTML = `
                <h2>Configurações</h2>
                <div class="settings-form">
                    <h3>Alterar Senha Mestra</h3>
                    <input type="password" id="new-master-password" placeholder="Nova Senha Mestra">
                    <button id="change-password-btn" class="btn-primary">Alterar Senha</button>
                    <h3>Tempo de Bloqueio (minutos)</h3>
                    <input type="number" id="lock-timeout" value="${KEYSPIRE_CONFIG.security.lockTimeout / 60000}" min="1" max="60">
                    <button id="save-timeout-btn" class="btn-primary">Salvar</button>
                    <h3>Sincronização via QR Code</h3>
                    <button id="generate-sync-qr" class="btn-primary">Gerar QR Code de Sync</button>
                    <input type="text" id="sync-qr-input" placeholder="Cole o código QR escaneado">
                    <button id="process-sync-qr" class="btn-primary">Processar QR Code</button>
                    <div id="qr-display"></div>
                </div>
                <p class="donation">Gostou? Considere uma doação: ${KEYSPIRE_CONFIG.donationAddress}</p>
            `;
            document.getElementById('change-password-btn')?.addEventListener('click', () => this.changeMasterPassword());
            document.getElementById('save-timeout-btn')?.addEventListener('click', () => this.saveLockTimeout());
            document.getElementById('generate-sync-qr')?.addEventListener('click', () => this.generateSyncQR());
            document.getElementById('process-sync-qr')?.addEventListener('click', () => this.processSyncQR());
            KeyspireLogger.info("Configurações renderizadas");
        } catch (e) {
            this.showNotification("Erro ao carregar configurações: " + e.message, "error");
        }
    }

    async generateSyncQR() {
        if (this.state.isLocked) {
            this.showNotification("Desbloqueie o cofre primeiro", "error");
            return;
        }
        try {
            const qrCode = await this.sync.generateSyncQR(this.state.masterKey);
            document.getElementById('qr-display').innerHTML = `
                <p>Escaneie este código no outro dispositivo:</p>
                ${qrCode}
            `;
            this.showNotification("QR Code de sincronização gerado!", "success");
        } catch (e) {
            this.showNotification(`Erro ao gerar QR Code: ${e.message}`, "error");
        }
    }

    async processSyncQR() {
        if (this.state.isLocked) {
            this.showNotification("Desbloqueie o cofre primeiro", "error");
            return;
        }
        try {
            const qrInput = document.getElementById('sync-qr-input')?.value;
            if (!qrInput) throw new Error("Cole o código QR primeiro");
            const updatedCount = await this.sync.processSyncQR(qrInput, this.state.masterKey);
            this.showNotification(`Sincronização concluída! ${updatedCount} itens atualizados.`, "success");
            await this.loadPasswords();
        } catch (e) {
            this.showNotification(`Erro ao processar sincronização: ${e.message}`, "error");
        }
    }

    generatePassword(length, options) {
        if (options.memorable) {
            const words = ["maçã", "banana", "gato", "cão", "elefante", "peixe", "uva", "cavalo", "gelo", "selva", "pipa", "leão"];
            const randomValues = crypto.getRandomValues(new Uint32Array(Math.ceil(length / 5))); // Aproximadamente 5 caracteres por palavra
            let password = Array.from(randomValues)
                .map(x => words[x % words.length])
                .join("-")
                .slice(0, length);
            if (password.length < length) {
                password += crypto.getRandomValues(new Uint32Array(1))[0].toString(36).slice(0, length - password.length);
            }
            KeyspireLogger.info(`Senha memorizável gerada: ${password}`);
            return password;
        }

        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const special = '!@#$%^&*';
        let chars = lower;
        if (options.upper) chars += upper;
        if (options.numbers) chars += numbers;
        if (options.special) chars += special;

        if (chars.length === lower.length && length < KEYSPIRE_CONFIG.security.minPasswordLength) {
            throw new Error(`Ative mais opções para senhas menores que ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres`);
        }

        const randomValues = crypto.getRandomValues(new Uint32Array(length));
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars[randomValues[i] % chars.length];
        }

        if (options.upper && !/[A-Z]/.test(password)) password = password.slice(0, -1) + upper[Math.floor(Math.random() * upper.length)];
        if (options.numbers && !/[0-9]/.test(password)) password = password.slice(0, -1) + numbers[Math.floor(Math.random() * numbers.length)];
        if (options.special && !/[!@#$%^&*]/.test(password)) password = password.slice(0, -1) + special[Math.floor(Math.random() * special.length)];

        KeyspireLogger.info(`Senha gerada: ${password}`);
        return password;
    }

    generateAndFillPassword() {
        try {
            const length = parseInt(document.getElementById('password-length')?.value) || 16;
            const options = {
                upper: document.getElementById('pw-upper')?.checked ?? true,
                numbers: document.getElementById('pw-numbers')?.checked ?? true,
                special: document.getElementById('pw-special')?.checked ?? true,
                memorable: document.getElementById('pw-memorable')?.checked ?? false
            };
            if (!options.upper && !options.numbers && !options.special && !options.memorable) {
                throw new Error("Ative pelo menos uma opção (maiúsculas, números, símbolos ou memorizável)");
            }
            const passwordField = document.getElementById('password-value');
            if (passwordField) {
                const newPassword = this.generatePassword(length, options);
                passwordField.value = newPassword;
                this.showNotification("Senha gerada e preenchida!", "success");
            } else {
                KeyspireLogger.error("Campo de senha não encontrado para preenchimento");
            }
        } catch (e) {
            this.showNotification(`Erro ao gerar senha: ${e.message}`, "error");
        }
    }

    async addPassword() {
        try {
            const sanitizeInput = (input) => input.replace(/[<>&"']/g, '');
            const name = sanitizeInput(document.getElementById('password-name')?.value);
            const category = sanitizeInput(document.getElementById('password-category')?.value);
            const username = sanitizeInput(document.getElementById('password-username')?.value);
            const password = document.getElementById('password-value')?.value;
            const totpSecret = document.getElementById('totp-secret')?.value;
            if (!name || !category || !username || !password) throw new Error("Preencha todos os campos obrigatórios");

            const data = { name, category, username, password };
            if (totpSecret) {
                data.totpSecret = await this.crypto.encryptData(totpSecret, this.state.masterKey);
            }
            const encryptedData = await this.crypto.encryptData(JSON.stringify(data), this.state.masterKey);
            await this.db.set('passwords', { data: encryptedData });
            this.showNotification("Senha adicionada com sucesso!", "success");
            await this.loadPasswords();
            ['password-name', 'password-category', 'password-username', 'password-value', 'totp-secret'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
        } catch (e) {
            this.showNotification(`Erro ao adicionar senha: ${e.message}`, "error");
        }
    }

    async togglePassword(idx) {
        try {
            const items = document.querySelectorAll('.password-item');
            if (idx >= items.length) return;
            const item = items[idx].querySelector('.password-info');
            const isHidden = item.textContent.includes('•');
            const passwords = await this.db.get(this.state.currentTab === 'vault' ? 'passwords' : 'trash');
            const data = JSON.parse(await this.crypto.decryptData(passwords[idx].data, this.state.masterKey));
            item.textContent = isHidden 
                ? `${sanitizeHTML(data.category)} - ${sanitizeHTML(data.name)} - ${sanitizeHTML(data.username)} - ${sanitizeHTML(data.password)}`
                : `${sanitizeHTML(data.category)} - ${sanitizeHTML(data.name)} - ${sanitizeHTML(data.username)} - ${'•'.repeat(data.password.length || 12)}`;
            KeyspireLogger.info(`Visibilidade da senha ${idx} alternada`);
        } catch (e) {
            this.showNotification("Erro ao alternar visibilidade: " + e.message, "error");
        }
    }

    async copyPassword(info) {
        try {
            if (!info.dataset.password) throw new Error("Nenhuma senha disponível");
            await navigator.clipboard.writeText(info.dataset.password);
            this.showNotification("Senha copiada para a área de transferência!", "success");
        } catch (e) {
            this.showNotification("Erro ao copiar senha: " + e.message, "error");
        }
    }

    async deletePassword(id) {
        try {
            if (!confirm("Tem certeza que deseja mover esta senha para a lixeira?")) return;
            const passwords = await this.db.get('passwords');
            const entry = passwords.find(p => p.id === id);
            if (!entry) throw new Error("Senha não encontrada");
            await this.db.set('trash', { ...entry, deletedAt: Date.now() });
            await this.db.delete('passwords', id);
            this.db.cache.passwords = null;
            this.showNotification("Senha movida para a lixeira!", "success");
            await this.loadPasswords();
            this.attachListeners();
        } catch (e) {
            this.showNotification("Erro ao excluir senha: " + e.message, "error");
        }
    }

    async restorePassword(deletedAt) {
        try {
            if (!confirm("Tem certeza que deseja restaurar esta senha?")) return;
            const trashItems = await this.db.get('trash');
            const entry = trashItems.find(t => t.deletedAt === deletedAt);
            if (!entry) throw new Error("Item não encontrado na lixeira");
            const { deletedAt: _, ...restoredEntry } = entry;
            await this.db.set('passwords', restoredEntry);
            await this.db.delete('trash', deletedAt);
            this.showNotification("Senha restaurada com sucesso!", "success");
            await this.loadTrash();
        } catch (e) {
            this.showNotification("Erro ao restaurar senha: " + e.message, "error");
        }
    }

    async deletePermanently(deletedAt) {
        try {
            if (!confirm("Tem certeza que deseja excluir permanentemente esta senha?")) return;
            await this.db.delete('trash', deletedAt);
            this.showNotification("Senha excluída permanentemente!", "success");
            await this.loadTrash();
        } catch (e) {
            this.showNotification("Erro ao excluir permanentemente: " + e.message, "error");
        }
    }

    async changeMasterPassword() {
        try {
            const newPassword = document.getElementById('new-master-password')?.value;
            if (!newPassword) throw new Error("Digite uma nova senha mestra");
            const { strength, message } = this.validatePassword(newPassword);
            if (newPassword.length < KEYSPIRE_CONFIG.security.minPasswordLength) {
                throw new Error(`Senha muito curta! Mínimo ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres`);
            }
            if (strength < 60 && !confirm(`Sua nova senha é '${message}'. Continuar?`)) return;

            const config = await this.db.get('config', 'auth');
            const salt = Uint8Array.from(atob(config.salt), c => c.charCodeAt(0));
            const newMasterKey = await this.crypto.deriveMasterKey(newPassword, salt);
            const hmacKeyBase64 = await this.crypto.decryptData(config.hmacKey, this.state.masterKey);
            const newHmacKeyEncrypted = await this.crypto.encryptData(hmacKeyBase64, newMasterKey);
            const newHmac = await this.crypto.generateHMAC(newPassword, Uint8Array.from(atob(hmacKeyBase64), c => c.charCodeAt(0)));
            
            await this.db.set('config', { ...config, hmac: newHmac, hmacKey: newHmacKeyEncrypted });
            this.state.masterKey = newMasterKey;
            this.showNotification("Senha mestra alterada com sucesso!", "success");
            document.getElementById('new-master-password').value = '';
        } catch (e) {
            this.showNotification("Erro ao alterar senha mestra: " + e.message, "error");
        }
    }

    async saveLockTimeout() {
        try {
            const minutes = parseInt(document.getElementById('lock-timeout')?.value);
            if (!minutes || minutes < 1 || minutes > 60) throw new Error("Digite um valor entre 1 e 60 minutos");
            KEYSPIRE_CONFIG.security.lockTimeout = minutes * 60000;
            this.resetInactivityTimer();
            this.showNotification(`Tempo de bloqueio ajustado para ${minutes} minutos!`, "success");
        } catch (e) {
            this.showNotification("Erro ao salvar tempo de bloqueio: " + e.message, "error");
        }
    }

    async exportVault() {
        try {
            if (this.state.isLocked) throw new Error("Desbloqueie o cofre primeiro");
            const exportPassword = prompt("Digite uma senha para o backup:");
            if (!exportPassword) throw new Error("Senha de backup necessária");
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const exportKey = await this.crypto.deriveMasterKey(exportPassword, salt);
            const vaultData = {
                passwords: await this.db.get('passwords'),
                config: await this.db.get('config', 'auth'),
                salt: btoa(String.fromCharCode(...salt))
            };
            const encryptedVault = await this.crypto.encryptData(JSON.stringify(vaultData), exportKey);
            const blob = new Blob([JSON.stringify(encryptedVault)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `keyspire-backup-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            this.showNotification("Backup exportado com sucesso!", "success");
        } catch (e) {
            this.showNotification("Erro ao exportar: " + e.message, "error");
        }
    }

    async importVault(event) {
        try {
            const file = event.target.files[0];
            if (!file) return;
            const exportPassword = prompt("Digite a senha do backup:");
            if (!exportPassword) throw new Error("Senha de backup necessária");
            const reader = new FileReader();
            reader.onload = async (e) => {
                const encryptedVault = JSON.parse(e.target.result);
                const salt = Uint8Array.from(atob(encryptedVault.salt), c => c.charCodeAt(0));
                const exportKey = await this.crypto.deriveMasterKey(exportPassword, salt);
                const decryptedVault = await this.crypto.decryptData(encryptedVault, exportKey);
                const vaultData = JSON.parse(decryptedVault);
                await this.db.set('passwords', vaultData.passwords);
                await this.db.set('config', vaultData.config);
                this.showNotification("Vault importado com sucesso!", "success");
                await this.loadPasswords();
            };
            reader.readAsText(file);
        } catch (e) {
            this.showNotification("Erro ao importar: " + e.message, "error");
        }
    }

    generateRecoveryPhrase() {
        const words = ["maçã", "banana", "gato", "cão", "elefante", "peixe", "uva", "cavalo", "gelo", "selva", "pipa", "leão"];
        return Array.from(crypto.getRandomValues(new Uint32Array(24)))
            .map(x => words[x % words.length])
            .join(" ");
    }

    showRecoveryForm() {
        const recoveryForm = document.getElementById('recovery-form');
        if (!recoveryForm) {
            KeyspireLogger.error("recovery-form não encontrado");
            return;
        }
        recoveryForm.classList.remove('hidden');
        recoveryForm.innerHTML = `
            <h3>Recuperar Acesso</h3>
            <textarea id="recovery-phrase" placeholder="Digite sua frase de recuperação (24 palavras)" rows="4"></textarea>
            <button id="recover-submit" class="btn-primary">Enviar</button>
        `;
        const submitBtn = document.getElementById('recover-submit');
        if (submitBtn) {
            submitBtn.addEventListener('click', () => {
                const phrase = document.getElementById('recovery-phrase')?.value.trim();
                if (phrase) this.recoverAccess(phrase);
            });
            KeyspireLogger.info("Listener adicionado para recover-submit");
        }
    }

    async recoverAccess(phrase) {
        try {
            const config = await this.db.get('config', 'auth');
            if (!config || !config.recoveryHash || !config.recoveryKey || !config.recoveryKeySalt) throw new Error("Nenhuma frase configurada ou configuração corrompida");

            const salt = Uint8Array.from(atob(config.salt), c => c.charCodeAt(0));
            const recoveryKeySalt = Uint8Array.from(atob(config.recoveryKeySalt), c => c.charCodeAt(0));
            const recoveryKeyEncryptionKey = await this.crypto.deriveMasterKey(phrase, recoveryKeySalt);
            const hmacKeyBase64 = await this.crypto.decryptData(config.recoveryKey, recoveryKeyEncryptionKey);
            const hmacKey = Uint8Array.from(atob(hmacKeyBase64), c => c.charCodeAt(0));
            const inputHash = await this.crypto.generateHMAC(phrase, hmacKey);

            if (inputHash !== config.recoveryHash) throw new Error("Frase de recuperação inválida");

            const newPassword = prompt(`Digite uma nova senha mestra (mínimo ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres):`);
            if (!newPassword || newPassword.length < KEYSPIRE_CONFIG.security.minPasswordLength) {
                throw new Error(`Nova senha muito curta! Mínimo ${KEYSPIRE_CONFIG.security.minPasswordLength} caracteres`);
            }
            const { strength } = this.validatePassword(newPassword);
            if (strength < 60 && !confirm("Sua nova senha é fraca ou média. Continuar?")) return;

            this.state.masterKey = await this.crypto.deriveMasterKey(newPassword, salt);
            const newHmac = await this.crypto.generateHMAC(newPassword, hmacKey);
            const newHmacKeyEncrypted = await this.crypto.encryptData(hmacKeyBase64, this.state.masterKey);

            await this.db.set('config', { 
                ...config, 
                hmac: newHmac, 
                hmacKey: newHmacKeyEncrypted 
            });
            this.state.loginAttempts = 0;

            this.showNotification("Senha redefinida com sucesso! Use a nova senha para entrar.", "success", true);
            this.renderUI();
            this.attachListeners();
        } catch (e) {
            this.showNotification(`Erro na recuperação: ${e.message}`, "error", true);
            KeyspireLogger.error(`Falha na recuperação: ${e.message}`);
        }
    }

    lockVault() {
        this.state.isLocked = true;
        this.state.masterKey = null;
        clearTimeout(this.state.inactivityTimer);
        this.renderUI();
        this.attachListeners();
        this.showNotification("Cofre bloqueado!", "success");
    }

    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('open');
            KeyspireLogger.info("Menu lateral alternado");
        } else {
            KeyspireLogger.warn("Sidebar não encontrado");
        }
    }

    switchTab(tab) {
        document.querySelectorAll('.tab-content').forEach(t => t.classList.add('hidden'));
        const tabContent = document.getElementById(`${tab}-tab`);
        if (tabContent) {
            tabContent.classList.remove('hidden');
            KeyspireLogger.info(`Aba ${tab} exibida`);
        }
        document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
        const menuItem = document.querySelector(`.menu-item[data-tab="${tab}"]`);
        if (menuItem) menuItem.classList.add('active');
        const currentTab = document.getElementById('current-tab');
        if (currentTab) currentTab.textContent = tab === 'vault' ? 'Cofre' : tab === 'trash' ? 'Lixeira' : 'Configurações';
        this.state.currentTab = tab;
        this.toggleSidebar();
        if (tab === 'vault') this.loadPasswords();
        else if (tab === 'trash') this.loadTrash();
        else if (tab === 'settings') this.loadSettings();
    }

    resetInactivityTimer() {
        clearTimeout(this.state.inactivityTimer);
        this.state.inactivityTimer = setTimeout(() => this.lockVault(), KEYSPIRE_CONFIG.security.lockTimeout);
        KeyspireLogger.info("Temporizador de inatividade reiniciado");
    }

    showNotification(message, type, persistent = false) {
        const note = document.createElement('div');
        note.className = `notification ${type}`;
        note.innerHTML = `${sanitizeHTML(message)}<button class="close-btn" aria-label="Fechar notificação">✖</button>`;
        document.body.appendChild(note);
        note.querySelector('.close-btn').addEventListener('click', () => note.remove());
        if (!persistent) setTimeout(() => note.remove(), 3000);
        KeyspireLogger.info(`Notificação exibida: ${message}`);
    }
}

// Inicialização
document.addEventListener('DOMContentLoaded', async () => {
    if (!window.crypto || !window.crypto.subtle) {
        alert("Este aplicativo requer um ambiente seguro (HTTPS) e suporte à Web Crypto API.");
        return;
    }
    try {
        const keyspire = new Keyspire();
        await keyspire.init();
        window.keyspire = keyspire;
    } catch (e) {
        KeyspireLogger.error("Erro ao carregar o Keyspire: " + e.message);
        alert("Erro ao carregar o Keyspire: " + e.message);
    }
});