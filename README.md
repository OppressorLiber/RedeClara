# Rede Clara

Um aplicativo Windows para encontrar computadores da rede local, consultar suas pastas compartilhadas e preparar o compartilhamento automaticamente. Interface clara, ícones vetoriais e movimento nativo em WPF.

## Usar

1. Baixe **RedeClara.exe** no [release mais recente](https://github.com/OppressorLiber/RedeClara/releases/latest). O ZIP também inclui instruções e configuração do runtime.
2. Abra o aplicativo e aceite o pedido de administrador do Windows.
3. Em uma rede privada, o app inicia a preparação automaticamente e busca os dispositivos.
4. Abra o app nos computadores que vão compartilhar arquivos. Em **Compartilhar pasta**, escolha a pasta, quem pode acessar e se o acesso permite somente leitura ou também alteração.
5. No outro PC, selecione o computador e a pasta. O Explorer usa a autenticação e as permissões do Windows; o PIN não substitui a senha da conta no acesso de rede.

Windows 10/11 x64 com .NET Framework 4.8 e Windows PowerShell 5.1. Não exige Python, Node ou um navegador para funcionar. O UAC é solicitado pelo manifesto do executável.

Em cada computador, execute uma cópia local do arquivo, por exemplo na Área de Trabalho ou em Downloads. Se transferir o app pela rede, copie-o primeiro para o PC de destino. Abrir diretamente por `\\computador\pasta` ou por uma unidade de rede mostra uma orientação antes da preparação.

## O que faz

- Busca IPv4 por ICMP e TCP/445, com 32 consultas simultâneas, limite de tempo e cancelamento.
- Mostra o nome quando resolvido, IP, computador local e resposta da porta de arquivos. Outros equipamentos podem aparecer na lista.
- Enumera pastas SMB com `NetShareEnum`, incluindo opção para mostrar compartilhamentos administrativos.
- Abre uma tela ampla do computador selecionado, com pastas em cartões, filtro, caminho e navegação por subpastas e arquivos, sem executar arquivos remotamente.
- Abre pastas no Explorer, copia caminhos e usa o diálogo nativo de mapeamento de unidade.
- Resolve conflitos de conta com **Trocar conta**: encerra somente conexões ociosas com o computador selecionado e abre o login do Windows novamente. Conexões com arquivos em uso são preservadas.
- Prepara os serviços de descoberta e compartilhamento; cria regras próprias de firewall para a interface escolhida, rede privada e sub-rede local.
- Faz diagnóstico, registra o estado anterior e permite desfazer os ajustes registrados pelo app. Não apaga os compartilhamentos do usuário ao desfazer a preparação.
- Compartilha uma pasta escolhida com a conta atual, um usuário específico ou **Todos**, com leitura por padrão ou leitura/gravação. Confere as permissões SMB e NTFS, preserva compartilhamentos existentes e guarda o estado anterior das permissões.
- Confere as regras internas de firewall que o Windows pode alterar ao criar o compartilhamento e restaura as mudanças reconhecidas dessa operação. Alterações desconhecidas interrompem a conclusão e ficam registradas para diagnóstico.
- Consulta automaticamente novos releases estáveis ao abrir e a cada seis horas, verifica SHA-256 e prepara a atualização em segundo plano. Aplica ao fechar e reinicia o app; há também a ação de reiniciar antes. Mantém uma cópia anterior e tenta restaurá-la se a troca/reabertura falhar.
- Anima entradas, transições, progresso e resposta dos botões; respeita o movimento reduzido do Windows e oferece um controle no app.

## Alcance

O administrador deste PC não ganha permissão administrativa em outro computador. A preparação deve ser executada em cada computador que vai publicar pastas. Redes públicas exigem a ação explícita **Confiar nesta rede e preparar**; redes gerenciadas por domínio recebem diagnóstico e preservam a política da organização.

A busca cobre até 1022 endereços; em redes maiores que /22, cobre apenas o trecho /24 local e informa isso na tela. IPv6, WS-Discovery, mDNS, inventário de roteadores e administração remota não fazem parte desta versão. Wi-Fi de convidados, isolamento do roteador e regras da organização podem bloquear a conexão.

SMB1 não é habilitado. O app preserva as políticas atuais de senha, acesso de convidado e assinatura SMB. Compartilhamentos administrativos dependem das permissões e regras de administração do destino. Enumerar um compartilhamento não comprova que a conta pode ler todos os seus arquivos.

## Escolher quem pode acessar

Faça essa configuração no computador que contém a pasta. **Conta atual** usa a conta exibida no app. Em **Usuário específico**, informe uma conta existente nesse computador, como `PC\usuario`, uma conta Microsoft como `MicrosoftAccount\email`, ou uma conta de domínio reconhecida pelo Windows. Um nome simples se refere a uma conta deste computador; o app não cria usuários nem concede direitos de administrador.

**Todos** concede o nível escolhido ao grupo Todos do Windows na pasta selecionada. O Windows pode aproveitar sua conta, credenciais salvas ou uma conexão existente, sem mostrar outra janela de login. A opção mantém a política de autenticação do computador: não habilita convidado nem remove senhas. Permissões próprias ou negações em arquivos e subpastas podem limitar o acesso a itens individuais.

O app cria um novo compartilhamento com o nome informado. Se esse nome já existe, ele é preservado: escolha outro nome ou ajuste o compartilhamento existente pelas ferramentas do Windows.

## Compilar e verificar

```powershell
.\build.ps1
.\test.ps1
```

O compilador do .NET Framework do Windows gera `dist/RedeClara.exe`; não há pacotes NuGet nem bibliotecas de terceiros no executável. `build.ps1 -QA` gera uma compilação de diagnóstico sem manifesto administrativo, usada para verificar a interface e a busca sem alterar a configuração da rede.

`test.ps1` prepara sua própria compilação de diagnóstico antes de testar. `package.ps1` gera executável, ZIP e checksums. O teste administrativo elevado em `tests/ElevatedSetupTests.cs` é manual e separado da suíte comum; sua execução explícita altera a configuração da rede privada selecionada.

Ao compilar esse teste elevado manualmente, inclua `src/NetworkIdentityInterop.cs` entre as fontes e `/resource:src\NetworkIdentityInterop.cs,RedeClara.NetworkIdentityInterop.cs` nos argumentos do compilador, além de Models, AdminConfigurator e NetworkDiscovery. A suíte comum já inclui a fonte e esse recurso automaticamente.

## Publicar atualizações

Altere a versão em `src/AssemblyInfo.cs`, compile e verifique. Crie uma tag com a mesma versão, por exemplo `v0.1.1`, e envie-a ao GitHub. O workflow valida a versão e publica executável, ZIP e `SHA256SUMS.txt`. Somente releases estáveis do repositório oficial são considerados pelo app.

Configurações e relatórios ficam em `%LOCALAPPDATA%\RedeClara`. O atualizador usa uma área protegida em `%PROGRAMDATA%\RedeClara\Updates`. Consulte [REFERENCES.md](REFERENCES.md) para as fontes consultadas e [DESIGN.md](DESIGN.md) para as decisões de interface e motion.
