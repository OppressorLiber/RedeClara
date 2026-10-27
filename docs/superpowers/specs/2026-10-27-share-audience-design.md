# Quem pode acessar a pasta

Referência: o usuário pediu a escolha de um usuário ou de Todos, como no assistente de compartilhamento do Windows enviado na conversa.

Ao criar um compartilhamento no computador que contém os arquivos, o Rede Clara oferecerá Conta atual (padrão), Usuário específico e Todos. Leitura permanece o padrão; leitura e alteração continua opcional. O usuário específico precisa existir e ser resolvido pelo Windows antes de qualquer alteração. Um nome simples é uma conta deste computador; contas qualificadas mantêm seu domínio. Todos é identificado pelo SID S-1-1-0, independentemente do idioma do Windows.

## Abordagens

- Abrir apenas o assistente do Windows: reutiliza a interface nativa, mas perde o preparo e a verificação automáticos pedidos para o app.
- Configurar o destinatário dentro da tela atual: mantém a operação simples, aplica permissões NTFS e SMB e confirma o SID autorizado. Esta é a implementação escolhida para o incremento solicitado.

O app cria somente o compartilhamento solicitado e mantém os anteriores. Não substitui o conteúdo de uma pasta nem edita um compartilhamento já existente com o mesmo nome. Não altera senhas, contas, permissões de administrador ou políticas de autenticação. Preserva as negações e as permissões preexistentes; ACLs próprias de subpastas podem continuar limitando itens individuais.

Todos amplia a permissão da pasta escolhida. Não significa exigir uma nova janela de login nem garantir acesso anônimo: o Windows pode usar uma sessão existente, credenciais salvas ou a política de convidado já configurada. A explicação contextual deve refletir a correção do usuário sobre o disco do Milena que já abre sem pedir senha.

## Verificação

Testar os três modos, dados inválidos e usuário inexistente; resolução antes de mutação; SID e direitos efetivamente aplicados; preservação de Deny, compartilhamentos anteriores, rollback e firewall. Testar seleção, bloqueio durante operação, campo condicional, aviso de Todos, leitura padrão, teclado, janela mínima e movimento reduzido. A suíte padrão não deve publicar uma pasta real para Todos. Declarar separadamente teste isolado, compilação e teste real entre PCs.
