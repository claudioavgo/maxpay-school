# Registro de uso e validação da IA

Registro retrospectivo desta sessão de implementação. Ferramenta de apoio: Codex. Provedor usado pelo produto: DeepSeek Flash. Os exemplos abaixo reproduzem prompts relevantes ou os resumem quando indicado. Não contêm credenciais.

| Pedido ou prompt | Resultado obtido | Aproveitado | Descartado/corrigido | Validação |
|---|---|---|---|---|
| “quero um app simples sem muita complicação” | Fluxos de depósito, revisão, extrato e perfil | EJS, SQLite e controles no servidor | Arquitetura adicional sem necessidade | Testes de fluxos e interfaces |
| “melhore essa tela para ser realmente um chat” | Balões, envio assíncrono e histórico do cliente | Conversa contínua e indicador de espera | Resposta duplicada e metadados técnicos na tela | Teste de navegador com envio, recarga, falha e layout móvel |
| “Qual transação eu fiz? A primeira?” | Resposta inicial apontava o depósito recente de R$ 100 | Identificação da ambiguidade de ordenação | Resposta do modelo estava errada e foi rejeitada | Consulta ao banco, contexto cronológico e teste com mais de 100 transações |
| “Não foi o depósito de 100 reais?” | Após a correção, o modelo distinguiu a primeira de R$ 4.462,30 da última pendente de R$ 100 | Fatos conferidos contra o banco | Concordância automática com a sugestão do cliente | Chamada real em base temporária, registrada durante a sessão |
| Revisar atendimento ao enunciado, resumo do pedido | Encontrados segredo de exemplo, CSP incompatível com demonstração e seed no reinício Docker | Correções limitadas aos problemas demonstrados | Alegação de que só a presença do HTML comprovaria XSS | Configuração sem exposição de valores, testes e execução no navegador |
| “acerte, quero tudo funcionando” | Validação de segredos, migração, inicialização preservando dados e documentação | Mecanismos testáveis e matriz de riscos | Nenhuma promessa de nota ou segurança absoluta | Suíte automatizada, testes de navegador e verificação de preservação |

## IA dentro do produto

O prompt de sistema está em `src/ai/assistant.ts`. Solicita português, respostas curtas, uso dos dados como fatos e nenhuma movimentação financeira. O contexto contém apenas transações do cliente no modo seguro, datas completas, primeira e última operação e totais concluídos. A conversa recente é limitada ao mesmo cliente.

A detecção de injeção é baseada em padrões; não é uma prova de que todo ataque será reconhecido. A mitigação principal é reduzir os dados acessíveis e não conceder ferramentas financeiras ao modelo. Os testes com provedor simulado validam essas propriedades. Chamadas reais validam integração e exemplos observados, sem garantir comportamento determinístico.

O PDF final pode aproveitar este registro, as capturas da sessão e os resultados dos testes. Acrescente nomes da equipe e as evidências escolhidas; não invente respostas, resultados ou ataques não executados.
