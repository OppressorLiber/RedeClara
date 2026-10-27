# Referências consultadas

Os repositórios abaixo foram baixados separadamente para consulta. Não foram incorporados como dependências, submódulos ou cópias do produto.

| Projeto | Revisão consultada | Aplicação |
|---|---|---|
| [Microsoft Windows classic samples](https://github.com/microsoft/Windows-classic-samples) | `434f6002bdf9cf9829406c3ff2b33387982d6168` | APIs NetShare e contexto de Function Discovery |
| [Microsoft WPF Samples](https://github.com/microsoft/WPF-Samples) | `811d01e95c8c929e68539d698d0a0609e94fd185` | KeySpline, relógios de animação e controles WPF |
| [WPF UI](https://github.com/lepoco/wpfui) | `ffebacd61058170cf63864b7d5aa730cffff848a` | Composição de navegação e estados dos controles; biblioteca não adicionada |
| [NetSparkle](https://github.com/NetSparkleUpdater/NetSparkle) | `2fc0da87e7857c54426ac4a4bc2f71b3243dca26` | Separação entre consulta, download e verificação da atualização; biblioteca não adicionada |

Documentação primária:

- [NetShareEnum](https://learn.microsoft.com/windows/win32/api/lmshare/nf-lmshare-netshareenum)
- [SMB1 não instalado por padrão e descoberta moderna](https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- [Regras de firewall](https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule)
- [Perfis de conexão](https://learn.microsoft.com/powershell/module/netconnection/set-netconnectionprofile)
- [Assinatura SMB](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing)
- [GitHub Releases API](https://docs.github.com/rest/releases/releases)

A verificação SHA-256 do app detecta downloads corrompidos e usa o release oficial por HTTPS. Ela não substitui uma assinatura Authenticode do editor. As referências a Ed25519 no NetSparkle não significam que essa biblioteca ou sua assinatura foram incorporadas ao Rede Clara.
