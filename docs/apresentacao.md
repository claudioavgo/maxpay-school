# Roteiro de apresentação: 15 minutos

Prepare duas sessões de navegador: cliente e analista/admin. Use dados fictícios. Confira `npm run typecheck`, `npm test` e `npm run test:browser` antes de apresentar. O serviço principal deve manter todas as flags desligadas.

| Tempo | Demonstração | Conceito defendido |
|---|---|---|
| 0 a 2 min | Login, conta e papéis | Problema, público, ativos, autenticação e autorização |
| 2 a 5 min | Depósito com arquivo, analista aprova, saldo creditado | Controle de acesso, integridade do comprovante e lógica de negócio |
| 5 a 8 min | `npm test -- tests/exploits/sqli.test.ts` e leitura do trecho correspondente | Mesmo ataque funcionando com flag e bloqueado com consulta parametrizada |
| 8 a 10 min | Baixar CSV, verificar, alterar valor e verificar novamente | Hash, assinatura, chave pública e integridade |
| 10 a 12 min | Chat: primeira transação e pergunta de continuação | IA real com dados do cliente, ordem cronológica e limites |
| 12 a 14 min | `npm test -- tests/exploits/ai.test.ts` e contexto capturado pelo teste | Exposição de dados ao provedor, injeção, minimização e mitigação |
| 14 a 15 min | Logs, matriz de riscos e conclusões | Evidências, escolhas técnicas e risco residual |

XSS é uma demonstração adicional executável: `npm run test:browser` usa um banco temporário e comprova no navegador o antes/depois. A suíte não altera a base usada na apresentação.

Para demonstrar adulteração, prefira editar uma cópia do CSV. Não altere o livro-razão da base principal: isso interrompe novas revisões enquanto a integridade estiver quebrada.

## Capturas para a entrega

- Conta antes/depois do depósito e decisão do analista.
- Resultado dos testes do mesmo ataque nos dois modos.
- CSV válido e CSV adulterado recusado.
- Pergunta e resposta do DeepSeek, incluindo uma pergunta de continuação.
- Contexto da IA vulnerável versus restrito, com dados exclusivamente fictícios.
- Evento de bloqueio ou integridade no painel administrativo.

Não exiba `.env`, cookies, chaves privadas nem backups. O relatório final precisa registrar método, evidência, impacto e correção. A aprovação dos testes não garante que um modelo real obedeça a um prompt malicioso: a exposição indevida do contexto ao provedor já constitui o risco demonstrado.
