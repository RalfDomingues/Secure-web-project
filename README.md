# 🔐 Secure Web Project

## 🎯 Objetivo

O objetivo deste trabalho é aplicar os **conceitos de segurança da informação** estudados na disciplina no desenvolvimento de um projeto de software.

O projeto consiste em um **sistema Web seguro** que utiliza banco de dados e implementa mecanismos de proteção baseados nos **pilares da segurança da informação**: confidencialidade, integridade e disponibilidade.

---

## 🧩 Requisitos de Segurança Implementados

### 🔑 Autenticação de Usuários
- Senhas armazenadas utilizando **função hash** (proteção contra vazamento de credenciais);
- Mecanismo para **impedir ataques de força bruta** na API de autenticação.

### 🧾 Registro de Logs
- Todas as ações do sistema são **registradas em log** para fins de auditoria e rastreabilidade.

### 🛡️ Proteção contra Vulnerabilidades
O sistema implementa medidas de mitigação contra:
- **SQL Injection**  
- **Caminho transversal (Path Traversal)**  
- **Cross-Site Scripting (XSS)**  
- **Cross-Site Request Forgery (CSRF)**  
- **Neutralização inadequada da saída para logs**

---

## 🧾 Auditoria e Registro de Logs
- Todas as ações críticas são registradas para rastreabilidade;
- Logs de uploads, downloads, criação de usuário, login e uso geral;
- Proteção contra injeção de dados maliciosos nos logs.

---

# 🔒 Novas Funcionalidades de Segurança (Versão 2.0)

## 🔐 1. Comunicação Segura com TLS (HTTPS)
A aplicação opera **exclusivamente** via HTTPS utilizando **TLS 1.2+**.

Inclui:
- Geração de certificado digital via OpenSSL;
- Uso de **Autoridade Certificadora (CA) local**;
- Instalação da CA raiz no Windows;
- Redirecionamento automático HTTP → HTTPS;
- Exibição do **cadeado de segurança** no navegador.

---

## 📁 2. Criptografia de Arquivos (AES-256-GCM)

Todos os arquivos enviados pelos usuários são **criptografados antes de serem armazenados**.

### ✔ Funcionamento:
- **Upload:** arquivo é carregado em memória e criptografado com AES-256-GCM;
- Armazenado com extensão `.enc`;
- Estrutura do arquivo:  
  **[IV][CIPHERTEXT][AUTH_TAG]**
- **Download:** arquivo é descriptografado dinamicamente antes de ser enviado.

### ✔ Benefícios:
- Confidencialidade dos arquivos em repouso;
- Integridade via tag de autenticação GCM;
- Chave segura em `FILE_ENC_KEY`;
- IV único para cada arquivo, conforme recomendações do NIST.

---

### 🌐 Acessar no navegador
Função	URL
Criar usuário	http://localhost:3000/register

Fazer login	http://localhost:3000/login

Dashboard (após login)	http://localhost:3000/dashboard

## ⚙️ Instruções de Uso

### ▶️ Executar o projeto
No terminal, dentro da pasta do projeto, execute:
```bash
npm run dev



