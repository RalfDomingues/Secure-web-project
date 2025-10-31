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



