# **Documentação Completa do Keyspire**  

## **🔐 Visão Geral**  
**Keyspire** é um gerenciador de senhas **offline e seguro**, desenvolvido para armazenar credenciais de forma criptografada no navegador. Ele utiliza:  
- **IndexedDB** para armazenamento local  
- **Web Crypto API** para criptografia AES-GCM e PBKDF2  
- **Sincronização via QR Code** entre dispositivos  
- **Frase de recuperação** para acesso em caso de senha esquecida  

🔗 **Acesso oficial:** [https://keyspirezmdsec.netlify.app/](https://keyspirezmdsec.netlify.app/)  

---

## **⚙️ Configurações Globais (`KEYSPIRE_CONFIG`)**  
```javascript
const KEYSPIRE_CONFIG = {
    dbName: "KeyspireDB",         // Nome do banco de dados
    version: 20,                 // Versão do esquema
    stores: {                    // Estrutura do IndexedDB
        passwords: { keyPath: "id", autoIncrement: true },  // Senhas
        config: { keyPath: "key" },                         // Configurações
        trash: { keyPath: "deletedAt" },                    // Lixeira
        sync: { keyPath: "syncId" }                         // Sincronização
    },
    security: {
        kdfIterations: 500000,     // Iterações do PBKDF2
        minPasswordLength: 12,      // Tamanho mínimo da senha
        maxLoginAttempts: 5,        // Tentativas de login
        lockTimeout: 300000,        // Bloqueio após 5min inativo (ms)
        syncKeyLength: 32,          // Tamanho da chave de sincronização
        syncExpiration: 300000      // Expiração do QR Code (5min)
    },
    donationAddress: 'hollowkevin92@walletofsatoshi.com',  // Doações
    officialWebsite: 'https://keyspirezmdsec.netlify.app/'  // Site
};
```

---

## **📜 Módulos Principais**  

### **1. 🖥️ KeyspireLogger**  
**Sistema de logs para debug e auditoria.**  
```javascript
KeyspireLogger.log("Mensagem", "nível", { contexto });  
KeyspireLogger.error("Erro crítico", { dados });  
KeyspireLogger.warn("Aviso", { contexto });  
KeyspireLogger.info("Informação", { dados });  
```
**Saída:**  
`[2025-04-10T12:00:00Z] ERROR: Erro crítico | Context: {"dados":123}`  

---

### **2. 🔐 KeyspireCrypto**  
**Manipulação criptográfica usando Web Crypto API.**  

#### **Métodos:**  
| Método | Descrição |
|--------|-----------|
| `deriveMasterKey(senha, salt)` | Deriva chave usando **PBKDF2-SHA512** |
| `encryptData(dados, chave)` | Criptografa com **AES-GCM** (IV + checksum) |
| `decryptData(dadosCripto, chave)` | Descriptografa e valida checksum |
| `generateHMAC(dados, chaveHMAC)` | Gera HMAC-SHA512 para verificação |
| `generateChecksum(dados)` | Hash SHA-256 para integridade |
| `generateTOTP(segredo)` | Gera código TOTP (6 dígitos) |

---

### **3. 🗃️ KeyspireDB**  
**Wrapper para IndexedDB com cache.**  

#### **Operações:**  
```javascript
const db = new KeyspireDB();  
await db.init();                 // Inicializa DB  
await db.get("passwords", id);   // Busca senha  
await db.set("passwords", data); // Salva senha  
await db.delete("trash", id);    // Remove item  
```

---

### **4. 📲 KeyspireSync**  
**Sincronização entre dispositivos via QR Code.**  

#### **Fluxo de Sincronização:**  
1. **Dispositivo A** gera QR Code (`generateSyncQR()`).  
2. **Dispositivo B** escaneia e processa (`processSyncQR()`).  
3. Os dados são **mesclados** (`mergeVaultData()`).  

```javascript
const sync = new KeyspireSync(crypto, db);  
const qrCodeHTML = await sync.generateSyncQR(chaveMestra);  
await sync.processSyncQR(dadosQR, chaveMestra);  
```

---

### **5. 🎨 QRCodeGenerator**  
**Geração de QR Codes sem bibliotecas externas.**  
```javascript
const qr = new QRCodeGenerator();  
const canvas = qr.generate("Dados para QR");  
```

---

### **6. 🏗️ Keyspire (Classe Principal)**  
**Gerencia autenticação, senhas e UI.**  

#### **Funcionalidades:**  
✅ **Autenticação segura** (PBKDF2 + HMAC)  
✅ **Armazenamento criptografado** (AES-256-GCM)  
✅ **Lixeira com restauração**  
✅ **Exportação/Importação** (backup criptografado)  
✅ **Tema claro/escuro**  
✅ **Bloqueio automático**  

#### **Métodos Principais:**  
| Método | Ação |
|--------|------|
| `createAccount(senha)` | Cria nova conta com frase de recuperação |
| `login(senha)` | Autentica e deriva chave mestra |
| `addPassword(dados)` | Criptografa e salva nova senha |
| `lockVault()` | Bloqueia o cofre |
| `exportVault()` | Gera backup criptografado |
| `importVault(arquivo)` | Restaura backup |

---

## **🔒 Fluxos de Segurança**  

### **1. 🔑 Derivação da Chave Mestra**  
1. Usuário digita senha.  
2. Gera **salt aleatório**.  
3. Deriva chave com **PBKDF2-SHA512 (500k iterações)**.  
4. Armazena **HMAC da senha** para verificação.  

### **2. 📦 Armazenamento de Senhas**  
- Cada entrada é **criptografada com AES-GCM**.  
- Possui **IV único** e **checksum SHA-256**.  
- **TOTP** (se configurado) é criptografado separadamente.  

### **3. ♻️ Recuperação de Acesso**  
1. Usuário insere **frase de recuperação (24 palavras)**.  
2. Deriva uma **chave de recuperação**.  
3. Permite **redefinir a senha mestra**.  

---

## **⚠️ Limitações**  
- **Offline-only** (não há sincronização em nuvem).  
- **Sem autenticação biométrica** (apenas senha).  
- **Depende do navegador** (não funciona em modo privado).  

---

## **📌 Exemplo de Uso**  
```javascript
// Inicialização
const keyspire = new Keyspire();  
await keyspire.init();  

// Login (se já tiver conta)  
await keyspire.login("minhaSenhaSuperSegura");  

// Adicionar nova senha  
await keyspire.addPassword({  
    name: "GitHub",  
    category: "Dev",  
    username: "user@github.com",  
    password: "s3nh@F0rTe!123",  
    totpSecret: "JBSWY3DPEHPK3PXP"  
});  

// Exportar backup  
await keyspire.exportVault();  
```

---

## **🔗 Links Úteis**  
🌐 **Site Oficial:** [https://keyspirezmdsec.netlify.app/](https://keyspirezmdsec.netlify.app/)  
💾 **Código-Fonte:** *GITHUB*
💰 **Doações:** Bitcoin para `hollowkevin92@walletofsatoshi.com`  

--- 

**📢 Nota:** Sempre use a versão oficial para garantir segurança.  
**🔄 Atualizações futuras:** Suporte a extensões de navegador e autenticação 2FA.
