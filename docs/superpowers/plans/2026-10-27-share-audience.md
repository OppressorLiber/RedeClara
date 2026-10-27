# Quem pode acessar a pasta — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Permitir escolher a conta atual, um usuário específico ou Todos ao compartilhar uma pasta.

**Architecture:** Reutilizar o pipeline administrativo existente com novos parâmetros de destinatário transportados em JSON/base64. Resolver e verificar o SID no processo que efetivamente cria o compartilhamento. Integrar a escolha à página WPF existente.

**Tech Stack:** C# 5, .NET Framework 4.8, WPF, Windows PowerShell 5.1 e SMB do Windows; sem dependências novas.

**Spec:** ../specs/2026-10-27-share-audience-design.md

## Global Constraints

- Conta atual e leitura por padrão; Todos somente quando escolhido.
- Não alterar autenticação, usuários, senhas, SMB1 ou permissões administrativas.
- Preservar ACLs existentes, Deny, compartilhamentos anteriores e mecanismos de snapshot, rollback e preservação do firewall.
- Não afirmar que Todos obriga login ou garante acesso sem autenticação.
- Não usar a suíte comum para conceder Todos em uma pasta real.

## Review Focus

- Conta simples deve resolver neste PC, sem confundir conta homônima de outro computador.
- SID de Todos deve funcionar em instalações de idiomas diferentes.
- Usuário inválido deve falhar antes de ACL, firewall ou novo compartilhamento.
- ACL preexistente ou grupos com Deny não podem ser apagados para concluir a operação.
- Elementos condicionais e suas mensagens precisam permanecer acessíveis em janela mínima e com movimento reduzido.

### Task 1: Destinatário administrativo

**Files:** src/AdminConfigurator.cs; tests/AdminTests.cs.

**Interfaces:** Preservar overloads de três argumentos; adicionar CreateShareAsync/BuildShareScript(string folder, string name, bool writable, string audience, string account), modos current/specific/everyone.

- [x] Criar e executar testes que falham para destinatário ausente/inválido e novo contrato.
- [x] Validar e resolver conta antes de mutações; selecionar SID de Todos de forma independente do idioma.
- [x] Aplicar e verificar direitos NTFS e SMB para o SID selecionado, preservando o pipeline de recuperação.
- [x] Executar testes de configuração e testes isolados de resolução sem alterar compartilhamentos reais.

### Task 2: Escolha na tela de compartilhamento

**Files:** src/MainWindow.xaml; src/Program.cs; tests/LayoutTests.cs.

**Interfaces:** Consumir o overload de Task 1; usar Conta atual, Usuário específico e Todos; campo e ajuda condicionais.

- [x] Criar e executar testes que falham para os novos controles e estados.
- [x] Integrar a seleção e a validação sem mudar a navegação principal.
- [x] Preservar leitura padrão, estado ocupado, teclado e movimento reduzido.
- [x] Renderizar as três escolhas e conferir a janela mínima.

### Task 3: Integração e entrega

**Files:** README.md; CHANGELOG.md; src/AssemblyInfo.cs; outputs externos ao repo.

- [x] Revisar o diff com um agente independente e corrigir problemas materiais.
- [x] Executar test.ps1 -Live, build e package; conferir versão e hashes.
- [ ] Publicar a atualização estável pelo fluxo GitHub já autorizado e verificar Latest e o resultado do atualizador anterior.
- [ ] Registrar limites da validação e atualizar o histórico no Obsidian.
