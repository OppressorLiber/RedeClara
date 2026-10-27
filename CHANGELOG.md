# Histórico de versões

## 0.1.3 — 27/10/2026

- Ao compartilhar uma pasta, permite escolher a conta atual, um usuário específico ou Todos.
- Configura e verifica as permissões do compartilhamento e da pasta para o destinatário escolhido, com leitura por padrão e alteração opcional.
- Valida o usuário antes de aplicar mudanças e identifica Todos independentemente do idioma do Windows.
- Explica que o Windows pode reutilizar uma conexão existente sem mostrar um novo login; mantém as políticas de autenticação e as permissões anteriores.

## 0.1.2 — 27/10/2026

- Corrige o carregamento do leitor de identidade da rede no PowerShell, sem carregar o executável por um caminho remoto.
- Ao abrir o app através de uma pasta de rede ou unidade mapeada, mostra uma orientação para copiar e abrir o arquivo localmente, antes de iniciar a preparação.
- Mantém as verificações do perfil Windows e as políticas de segurança do .NET/PowerShell.

## 0.1.1 — 27/10/2026

- Novo botão **Trocar conta** para resolver conflito de credenciais do Windows (1219), encerrando somente conexões ociosas com o computador selecionado.
- Troca sem forçar o fechamento de arquivos ou apagar a configuração de unidades mapeadas.
- Campo identificado para o usuário do computador remoto e ajuda sobre conta local, conta Microsoft, senha e PIN. A senha continua no diálogo do Windows.
- Dados deste computador mais claros e ação para copiar o usuário.
- Ações de arquivo são ocultadas enquanto o app mostra o estado de conexão.

## 0.1.0 — 27/10/2026

Primeiro release do Rede Clara para Windows x64.

- Descoberta de dispositivos IPv4 da rede selecionada e conexão por nome/IP.
- Tela ampla de cada computador, com compartilhamentos, subpastas, arquivos, filtro e retorno por nível.
- Pastas administrativas opcionais e autenticação pelo diálogo nativo do Windows.
- Abertura no Explorer, cópia de caminhos e mapeamento pelo diálogo nativo.
- Preparação automática de redes privadas, regras próprias de firewall limitadas à sub-rede e restauração dos ajustes registrados.
- Criação de compartilhamento para uma pasta escolhida e a conta indicada.
- Interface clara, ícones próprios, transições e movimento reduzido.
- Atualizações automáticas a partir dos releases estáveis oficiais, com SHA-256, estágio protegido e cópia anterior para recuperação.

Acesso às pastas continua condicionado às permissões e às credenciais do Windows. Esta versão trabalha com IPv4 e não implementa administração remota ou descoberta WS-Discovery/mDNS.
