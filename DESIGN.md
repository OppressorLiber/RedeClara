# Rede Clara — visual e movimento

Brief de implementação para o aplicativo Windows nativo em WPF/.NET Framework 4.8. A direção já está autorizada: aparência inspirada na clareza e no cuidado de interfaces Apple, com comportamento e controles acessíveis do Windows.

## Intenção e identidade

- Pessoa: alguém em casa ou em uma pequena rede que quer encontrar um computador e abrir seus recursos com confiança.
- Ação principal: localizar um computador, selecionar e usar a ação disponível no painel de detalhes.
- Sensação: uma mesa de trabalho clara, ordenada e responsiva. Informações técnicas aparecem no momento em que ajudam a decidir.
- Domínio: computadores próximos, descoberta na rede, conexões, pastas compartilhadas, nome do equipamento, endereço local, disponibilidade e acesso.
- Mundo de cores: porcelana branca, plástico cinza claro, vidro fosco, azul de sinal, grafite dos rótulos e verde discreto de conexão.
- Assinatura: um pequeno conjunto de computadores desenhados em vetor, ligado por uma linha azul fina; o computador selecionado reaparece maior no detalhe. O mesmo traço aparece no ícone do aplicativo, vazio da lista, linha selecionada, cabeçalho do detalhe e status de descoberta.
- Evitar: grade de cartões com métricas sem função; cabeçalho enorme com instruções; detalhes de rede tratados como erro por padrão. Usar lista de equipamentos, uma ação clara e detalhes progressivos.

## Composição

Janela preferida de 1180 × 760 DIP, mínima de 980 × 640. Preservar a barra de título, redimensionamento e botões de janela reconhecíveis do Windows. Não imitar os controles coloridos de janela do macOS.

1. Navegação de 228 DIP: marca pequena, destinos com ícone + rótulo e estado local no rodapé. Mesmo fundo perolado do canvas; separação apenas por linha muito suave.
2. Área principal com margem externa de 24 DIP. Cabeçalho com título de 28 DIP, subtítulo curto e ação de descoberta alinhada à direita.
3. Lista de computadores com largura de 336 DIP e detalhe flexível. Em janelas menores, lista de 300 DIP; não esmagar os rótulos do detalhe.
4. Segmentação compacta acima da lista para categorias que realmente existirem. Não exibir filtros sem efeito.
5. Linha de computador de 72–80 DIP: ícone de 36, nome em semibold, descrição curta, status legível por texto e símbolo. IP secundário, sem competir com o nome.
6. Detalhe: ícone grande de 64–80 DIP, nome de 22 DIP, estado, ação principal e grupos menores de informações. A ação principal deve ser o ponto focal; nenhum bloco de introdução deve empurrá-la para fora da tela.

O vazio mantém a estrutura da tela: ícone de dois computadores, “Nenhum computador encontrado”, uma orientação curta e a ação de buscar. Uma falha de descoberta mantém os resultados anteriores visíveis e explica a falha junto da ação.

## Tokens WPF

Usar `ResourceDictionary` compartilhado e estilos reais de `Button`, `TextBox`, `ListBoxItem` e `TabItem`/`RadioButton`; não substituir controles por `Border` com clique.

| Recurso | Valor | Uso |
|---|---|---|
| `PearlCanvasBrush` | `#F5F7FA` | janela e navegação |
| `PorcelainSurfaceBrush` | `#FFFFFF` | lista e detalhe |
| `InsetControlBrush` | `#EFF2F6` | busca e controles embutidos |
| `PowderSelectionBrush` | `#E7F0FF` | equipamento e navegação selecionados |
| `SignalBlueBrush` | `#0068E8` | ação principal, foco e conexão desenhada |
| `GraphiteTextBrush` | `#1F2937` | nomes e texto principal |
| `SecondaryTextBrush` | `#59697E` | descrições e metadados |
| `SoftEdgeBrush` | `#DEE4EC` | borda sutil de controle |
| `ConnectedBrush` | `#167344` | disponibilidade, sempre com rótulo |
| `WarningBrush` | `#8C5B00` | aviso contextual |
| `ErrorBrush` | `#B42332` | erro com explicação e recuperação |

Profundidade: superfícies brancas com uma sombra curta e discreta, aplicada ao contêiner estático. Não animar sombra nem aplicar `DropShadowEffect` individualmente a cada linha. Bordas ficam reservadas a campos e separações necessárias.

Espaçamento em base de 4 DIP: 4/8 entre ícone e texto; 12–16 dentro de controles e linhas; 20–24 entre grupos; 32 entre áreas maiores. Botões de 40–44 DIP de altura, alvos de ícone com área de 40 × 40, raio 9–10; cartões de raio 14–16. Não usar raio de pílula em todos os controles.

Tipografia: `Segoe UI`, escolhida por legibilidade e integração nativa no Windows. Corpo 14; legenda 12; nome de equipamento 14–15 semibold; título de grupo 16 semibold; detalhe 22 semibold; título da página 28 semibold. Peso e cor constroem hierarquia. Configurar números tabulares onde suportado e largura estável para contagens e endereços. Evitar caixa alta extensa.

Ícones vetoriais: computadores, rede, pasta, lupa, atualizar, seta externa, ajustes e informação. Traço arredondado de 1.5–1.75 DIP em grade de 24; caixas ópticas consistentes, sem emoji como ícone. `DrawingImage`/`GeometryDrawing` ou `Path` para linhas simples; conservar nitidez ao escalar e usar `SnapsToDevicePixels`/`UseLayoutRounding`. Ilustração de vazio pode ser mais detalhada, mantendo as mesmas proporções e traço.

## Movimento

O pedido de bastante movimento é atendido por respostas distribuídas nos eventos reais da interface, sem movimento permanente nos dados. Toda ação funciona imediatamente; animações não atrasam busca, seleção ou abertura. Conteúdo permanece clicável durante a entrada.

WPF: `DoubleAnimationUsingKeyFrames` com `SplineDoubleKeyFrame`, `RenderTransform` e `Opacity`. Aplicar a curva no keyframe final. Não supor aceleração apenas pela existência de uma animação WPF: conferir o aplicativo renderizado.

| Token | Curva exata / duração |
|---|---|
| `EaseOut` | `KeySpline="0.23,1 0.32,1"` |
| `EaseInOut` | `KeySpline="0.77,0 0.175,1"` |
| `DrawerEase` | `KeySpline="0.32,0.72 0,1"` |
| `PressDuration` | 160 ms |
| `SmallSurfaceDuration` | 200 ms |
| `DialogDuration` | 250 ms |

| Evento | Propósito e implementação |
|---|---|
| Primeira abertura da janela | Uma entrada: conteúdo de `Opacity 0→1` e `TranslateY 8→0`, 250 ms `EaseOut`; no máximo três grupos com atraso de 30 ms. Não repetir ao restaurar a janela. |
| Hover de botão | Resposta discreta: trocar superfície/contorno; transição curta de opacidade de uma camada, 125 ms. Somente para ponteiro mouse real. |
| Pressionar botão | Feedback: `ScaleTransform 1→0.97`, 160 ms `EaseOut`; retornar a 1 ao soltar ou perder captura. `RenderTransformOrigin="0.5,0.5"`. |
| Trocar segmento com mouse | O indicador desliza por `TranslateTransform`, 200 ms `EaseInOut`; as páginas ficam interativas imediatamente. |
| Selecionar computador com mouse | Destaque da linha por opacidade, 125 ms; novo detalhe em `Opacity 0→1`, 200 ms e deslocamento de 8 DIP. A lista permanece estável. |
| Navegar por teclado | Estado, seleção, foco e conteúdo mudam imediatamente. Não animar a navegação entre linhas nem o acionamento de atalhos. |
| Surgir computador novo | Apenas a linha nova: opacidade e deslocamento vertical de 8 DIP, 200 ms `EaseOut`. Não reapresentar toda a lista a cada atualização. |
| Alterar disponibilidade | Troca de texto e ícone imediatamente; fade de 125 ms apenas na camada de status. Nenhum efeito de piscar. |
| Descoberta em andamento | Progresso indeterminado restrito à ação de busca; rotação linear de 800 ms somente enquanto a operação estiver ativa. Mostrar “Buscando…” em texto. Parar ao concluir, cancelar ou ocultar a janela. |
| Abrir superfície auxiliar | Popover nasce no ponto do acionador: escala 0.95→1 e opacidade, 200 ms `EaseOut`. Modal central: escala 0.96→1, 250 ms e backdrop com a mesma duração. |
| Mensagem de resultado | Toast com texto persistente enquanto relevante, opacidade e `TranslateY 8→0`, 200 ms `EaseOut`; sair pelo mesmo lado. Erro importante permanece inline e não depende de toast. |
| Abrir seção de detalhes | Preferir visibilidade simples ou fade de 200 ms. Não animar `Width`, `Height`, `Margin` ou posições de layout a cada frame. |

Interrupção: retarget a partir do valor atual; `HandoffBehavior.SnapshotAndReplace`, sem relógios acumulados. Definir o valor base final e remover o relógio após conclusão. Uma nova seleção cancela a entrada anterior e não produz fila. Escalas pertencem à superfície clicável, não a toda a página.

Movimento reduzido: respeitar `SystemParameters.ClientAreaAnimation` e um controle “Reduzir animações” nas preferências se já houver área de preferências. Reagir a alterações do sistema. Quando reduzido, retirar translação, escala, rotação e stagger; usar mudança instantânea ou fade de 125 ms. Progresso usa texto estático. Em alto contraste, usar `SystemColors` e contornos visíveis.

## Teclado, foco e acessibilidade

- Ordem de Tab: navegação, busca/filtro, lista, ação do detalhe, ações secundárias. Não criar foco em ornamentos.
- `ListBox` mantém Setas, Home/End e seleção; Enter aciona a ação padrão apenas quando aplicável. Space continua acionando botões normalmente.
- Escape fecha a superfície auxiliar ou cancela uma busca cancelável; foco volta ao acionador. Diálogo modal recebe foco e impede interação com a janela proprietária.
- Foco visível de 2 DIP em azul com afastamento de 2 DIP, sem ser removido pelo estilo customizado. Seleção e foco são estados diferentes.
- `AutomationProperties.Name` em todos os botões só com ícone; estado de conexão legível por leitor de tela, sem depender de verde/vermelho.
- Estados completos em controles: normal, hover, pressionado, foco, desabilitado e ocupado. Texto de status não deve ser o único elemento que muda sem anúncio ou foco previsível.
- Manter contraste verificável, nome do equipamento sem truncamento desnecessário e tooltip para valor completo onde houver corte. Seleção não pode deixar texto claro em fundo azul claro.
- Verificar 100%, 125%, 150% e 200% de DPI, tela mínima e nomes longos. Não usar `Viewbox` na janela inteira para esconder problemas de layout.

## Checklist para a implementação e revisão

- [ ] Uma navegação, uma lista funcional e um detalhe principal; nenhuma versão antiga duplicada.
- [ ] Recursos de cor, raio, tipografia e animação compartilhados.
- [ ] Vetores consistentes em lugar de emojis ou imagens ampliadas sem resolução.
- [ ] Estado vazio, buscando, com resultados, offline, falha e ação indisponível conferidos.
- [ ] Ação principal clara e metadados secundários agrupados.
- [ ] Animações por evento, interrupção rápida, movimento reduzido e ausência de loops em repouso.
- [ ] Teclado completo, foco visível e nomes de automação conferidos.
- [ ] Janela realmente aberta e capturada; conferir visual em tamanho preferido/mínimo e DPI. Build e inspeção estática não provam a qualidade do movimento.

## Orientações consultadas e disponibilidade

Aplicadas: `C:\Users\dbalb\.codex\skills\interface-design\SKILL.md`, seu `CODEX-INTEGRATION.md`, `C:\Users\dbalb\.codex\skills\animate\SKILL.md`, seu `CODEX-INTEGRATION.md` e `RECIPES.md`. Tradução para a pilha WPF existente: manter controles nativos e não instalar bibliotecas de movimento para fades e transforms.

Superpowers: na consulta inicial, a busca limitada em `.codex\plugins`, `.codex\skills` e `.agents\skills` não encontrou o `SKILL.md`; o catálogo retornou **Superpowers**, ID `plugins~Plugin_60aea7460bd4819199fd97a9553a5e12`, com `installed: false`. Durante a sessão, os arquivos locais da versão 7.0.1 passaram a estar disponíveis em `C:\Users\dbalb\.codex\plugins\cache\openai-curated-remote\superpowers\7.0.1\skills`. Foram então consultados `using-superpowers`, `requesting-code-review`, `systematic-debugging` e `brainstorming`. A investigação de layout usou medição isolada antes de recomendar alterações; o ícone foi uma tarefa pequena de direção já definida, sem nova rodada de perguntas.

## Assets reais e revisão de layout

- `assets/mark.svg`: marca original em vetor, quadrado azul `#0069DE` com cantos arredondados e glifo branco de rede local. Inclui título e descrição no SVG.
- `assets/RedeClara.ico`: quatro imagens com alpha e 32 bits, em 16, 32, 48 e 256 pixels. A versão de 16 pixels tem traço ajustado para leitura em tamanho pequeno. O diretório ICO foi conferido e o arquivo abriu pela API nativa `System.Drawing.Icon`.
- `assets/mark-preview.png`: prévia de 256 pixels, derivada da mesma geometria e conferida visualmente. O SVG continua sendo a fonte editável.

O glifo liga explicitamente o nó central à barra inferior; manter essa ligação ao reproduzir a marca no XAML.

Revisão da primeira implementação, antes das correções do implementador: carregar o XAML isoladamente e medir um conteúdo de 1164 × 761 DIP reproduziu campos de texto com 61 DIP de altura. A causa foi `PART_ContentHost.Margin` repetindo `TextBox.Padding`; zerar somente a margem do host na árvore em memória reduziu o campo para 41 DIP. Com a mensagem real de acesso negado, `ShareEmpty` pediu 220 DIP em uma linha com apenas 165 DIP; o ícone começou em −28 DIP e o botão terminou em 192 DIP, explicando os dois cortes. A área de mensagem/recuperação precisa rolagem ou ações distribuídas em linhas adequadas.

Na animação de revelação, o keyframe final único utiliza o valor efetivo anterior como origem. Um relógio anterior em `HoldEnd` mantém opacidade efetiva 1 mesmo após mudar o valor base para 0, eliminando o fade da segunda entrada. Usar origem explícita para a revelação ou remover o relógio anterior antes de definir o estado inicial; ao concluir, guardar o valor final como base e remover o relógio.
