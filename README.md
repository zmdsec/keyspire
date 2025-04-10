# Documentação do Keyspire

## Visão Geral
Keyspire é um gerenciador de senhas seguro e offline que utiliza criptografia moderna para proteger seus dados. Este documento fornece uma visão geral da arquitetura, componentes principais e funcionalidades do sistema.

## Configurações Globais
```javascript
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
```

### Parâmetros de Configuração
- **dbName**: Nome do banco de dados IndexedDB
- **version**: Versão do esquema do banco de dados
- **stores**: Configuração dos object stores (tabelas)
- **security**: Parâmetros de segurança
  - `kdfIterations`: Iterações para derivação de chave PBKDF2
  - `minPasswordLength`: Comprimento mínimo da senha mestra
  - `maxLoginAttempts`: Tentativas de login antes de bloquear
  - `lockTimeout`: Tempo de inatividade antes de bloquear (ms)
  - `syncKeyLength`: Tamanho da chave de sincronização
  - `syncExpiration`: Tempo de expiração da sincronização (ms)

## Módulos Principais

### 1. KeyspireLogger
Sistema de logging centralizado com níveis de severidade.

```javascript
class KeyspireLogger {
    static log(message, level = 'info', context = {})
    static error(message, context = {})
    static warn(message, context = {})
    static info(message, context = {})
}
```

### 2. KeyspireCrypto
Módulo de criptografia que implementa operações seguras.

#### Métodos Principais:
- `deriveMasterKey(password, salt)`: Deriva uma chave mestra usando PBKDF2
- `encryptData(data, key)`: Criptografa dados com AES-GCM
- `decryptData(encrypted, key)`: Descriptografa dados
- `generateHMAC(data, hmacKey)`: Gera HMAC-SHA512
- `generateChecksum(data)`: Gera checksum SHA-256
- `generateTOTP(secret)`: Gera código TOTP

### 3. KeyspireDB
Wrapper para IndexedDB com cache integrado.

#### Métodos Principais:
- `init()`: Inicializa o banco de dados
- `get(storeName, key)`: Obtém dados
- `set(storeName, data)`: Armazena dados
- `delete(storeName, key)`: Remove dados

### 4. QRCodeGenerator
Gerador de QR Code sem dependências externas.

### 5. KeyspireSync
Sistema de sincronização via QR Code.

#### Funcionalidades:
- `generateSyncQR(masterKey)`: Gera QR Code para sincronização
- `processSyncQR(qrData, masterKey)`: Processa QR Code recebido
- `mergeVaultData(existing, incoming)`: Mescla dados locais e remotos

### 6. Keyspire (Classe Principal)
Gerencia o estado da aplicação e coordena os módulos.

#### Funcionalidades Principais:
- Autenticação e gerenciamento de conta
- CRUD de senhas
- Lixeira com recuperação
- Exportação/importação do cofre
- Sincronização entre dispositivos
- Gerenciamento de temas
- Notificações

## Fluxos Principais

### 1. Criação de Conta
1. Usuário define senha mestra
2. Sistema deriva chave mestra com PBKDF2
3. Gera chave HMAC e frase de recuperação
4. Armazena configurações de autenticação

### 2. Login
1. Usuário insere senha mestra
2. Sistema deriva chave mestra
3. Verifica HMAC da senha
4. Desbloqueia cofre se válido

### 3. Gerenciamento de Senhas
- **Adicionar**: Criptografa e armazena no IndexedDB
- **Visualizar**: Descriptografa sob demanda
- **Editar**: Atualiza registro criptografado
- **Excluir**: Move para lixeira
- **Restaurar**: Recupera da lixeira

### 4. Sincronização via QR Code
1. Dispositivo A gera QR Code com dados criptografados
2. Dispositivo B escaneia QR Code
3. Dados são mesclados com cofre local

## Considerações de Segurança
- Todas as operações criptográficas usam Web Crypto API
- Dados sensíveis nunca armazenados em texto plano
- Verificação de integridade via checksum
- Limite de tentativas de login
- Bloqueio automático por inatividade

## Limitações
- Requer HTTPS para Web Crypto API
- Dados armazenados apenas localmente
- Versão beta - pode conter bugs

## Exemplo de Uso
```javascript
// Inicialização
const keyspire = new Keyspire();
await keyspire.init();

// Após autenticação:
await keyspire.addPassword({
    name: "Exemplo",
    category: "Web",
    username: "user@example.com",
    password: "s3cr3tP@ss"
});

const passwords = await keyspire.loadPasswords();
```

## Notas de Desenvolvimento
- Projeto em fase beta
- Testado apenas em navegadores modernos
- Melhorias planejadas para versões futuras

Para suporte ou contribuições, contate o mantenedor.
