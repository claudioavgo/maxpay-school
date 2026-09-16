# Validação do MaxPay

Data: 16/09/2026. Escopo: correções de configuração criptográfica, preservação no Docker, demonstração de XSS e alinhamento da documentação. O relatório final em PDF não foi gerado.

## Evidências executáveis

| Verificação | Como repetir | Evidência |
|---|---|---|
| Tipos TypeScript | `npm run typecheck` | Concluído sem erros |
| Integração, fluxos e ataques/retestes | `npm test` | [Saída da suíte](evidence/tests.txt) |
| XSS no navegador e chat | `npx playwright install chromium` e `npm run test:browser` | [Execução real e bloqueio após correção](evidence/browser.txt) |
| Inicialização e reinício Docker | Construir imagem, iniciar com segredos aleatórios e volumes, alterar saldo de teste, reiniciar e consultar novamente | [Resultado do contêiner isolado](evidence/docker.txt) |
| Preservação na troca de chaves | `tests/setup.test.ts`; instalação existente: parar serviço e executar `npm run keys:rotate` | [Verificação da base local](evidence/keys.txt) |
| Dependências de produção | `npm audit --omit=dev --audit-level=high` | Nenhuma vulnerabilidade conhecida reportada na execução |

A suíte usa bancos temporários e chamadas simuladas para o provedor de IA. O teste de XSS usa Chromium e verifica um efeito observável de execução do JavaScript, não apenas a presença de HTML. No teste de Docker, um saldo alterado para 123456 centavos e os cinco usuários permaneceram após reiniciar. O contêiner e seus volumes de teste foram removidos depois.

## Alterações verificadas

1. SESSION_SECRET deixou de usar o exemplo; MASTER_KEY_HEX passou a ser independente e aleatória. Segredos inválidos impedem a inicialização.
2. A migração mantém cópia privada do banco, configuração e arquivos cifrados. CPF e comprovantes são recriptografados; o HMAC de busca do CPF é atualizado. As assinaturas RSA permanecem válidas. Sessões antigas deixam de funcionar e exigem novo login.
3. O servidor inicializa os dados somente em banco vazio. O seed manual exige `--reset` para substituir dados existentes.
4. A flag XSS desliga a CSP no experimento vulnerável. Sem a flag, conteúdo é escapado e CSP permanece ativa.
5. O teste de risco de IA captura o conteúdo enviado ao provedor: o CPF de outro cliente aparece no modo vulnerável e não aparece no modo seguro. A mesma resposta adversa simulada é filtrada apenas no modo seguro.
6. PLAN.md e README descrevem DeepSeek, revisão por regras, proteção das sessões e limites reais, sem atribuir funções inexistentes ao sistema.

## Limites da conclusão

Esta validação comprova os cenários executados, não ausência absoluta de falhas. Não houve pentest externo, teste de carga ou avaliação jurídica. O ambiente continua local, com dados fictícios e certificado autoassinado. Não há integração com bancos. A nota também depende da apresentação oral e das evidências escolhidas pela equipe.

As capturas de tela escolhidas pela equipe, o registro de IA e a matriz de riscos devem compor o relatório final de 6 a 10 páginas, conforme o enunciado.
