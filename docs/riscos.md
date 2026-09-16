# Ameaças e matriz de riscos

Escopo: aplicação acadêmica MaxPay com dados fictícios. Avaliação qualitativa antes dos controles. Probabilidade e impacto: baixo, médio ou alto. As flags vulneráveis demonstram a ausência do controle; ficam desligadas no uso normal.

Ativos: credenciais, sessões, CPF, saldos, transações, comprovantes, chaves criptográficas, conversas e logs. Fronteiras de confiança: navegador/servidor, servidor/banco e arquivos, servidor/DeepSeek. Clientes têm acesso próprio; analistas revisam; administradores consultam eventos e exportações.

| Superfície e ameaça | Prob. | Impacto | Risco | Controle e evidência | Limite residual |
|---|---|---|---|---|---|
| Login: adivinhação de senha | Alta | Alto | Alto | Argon2id, limite de tentativas, bloqueio, MFA; auth.test.ts | Sessão já roubada não exige novo MFA em cada ação |
| API: leitura de outra conta/arquivo | Alta | Alto | Alto | Papel e propriedade; idor.test.ts | Perfis privilegiados precisam acesso operacional |
| Busca: injeção SQL | Alta | Alto | Alto | Parâmetros SQL; sqli.test.ts | Novas consultas precisam manter esse padrão |
| Descrição: XSS persistente | Alta | Alto | Alto | Escape EJS e CSP; xss.test.ts e test:browser | Modo vulnerável é deliberadamente inseguro |
| Upload: conteúdo não permitido | Média | Alto | Alto | Tamanho, magic bytes, nomes aleatórios, fora do diretório público; upload.test.ts | Não há antivírus nem análise profunda de PDF |
| API: exposição de CPF e hash de senha | Alta | Alto | Alto | Seleção explícita de campos e mascaramento; exposure.test.ts | Texto livre exige cuidado do usuário |
| Sessão: exposição do cookie | Média | Alto | Alto | Cookie seguro, sessão autenticada e timeout; exposure.test.ts | Não há revogação central de todas as sessões por dispositivo |
| Arquivo/livro-razão adulterado | Média | Alto | Alto | AES-GCM, SHA-256 e RSA; integrity.test.ts | Comprometimento de servidor e chave juntos excede o modelo local |
| Transferência/depósito: fraude de valor ou autoaprovação | Alta | Alto | Alto | Inteiros positivos, saldo disponível, revisão privilegiada e decisão única; logic.test.ts e flows.test.ts | Confirmação do comprovante é humana, sem consulta bancária |
| Chaves conhecidas ou ausentes | Média | Alto | Alto | Valores aleatórios obrigatórios, migração com backup; setup.test.ts | Backup e máquina local precisam proteção |
| Chat: prompt injection e dados de outro cliente | Alta | Alto | Alto | Contexto restrito, instruções separadas, filtro CPF e logs; ai.test.ts e deepseek.test.ts | Modelo não determinístico; detecção textual não cobre todas as formas |
| Chat: interpretação financeira incorreta | Alta | Médio | Alto | Ordem explícita, destaques e totais calculados; deepseek.test.ts | Totais de períodos parciais e respostas livres exigem conferência |
| Disponibilidade: excesso de requisições/provedor indisponível | Média | Médio | Médio | Rate limit, timeout e mensagem de falha | Aplicação local sem alta disponibilidade |
| Docker: perda de dados no reinício | Média | Alto | Alto | Volumes e inicialização apenas de banco vazio; setup.test.ts | Reset explícito e remoção de volumes continuam destrutivos |
| Exportações: reidentificação | Média | Médio | Médio | Pseudônimo e faixa etária; privacy.ts | Pseudonimização não elimina reidentificação por combinação de dados |

Os mecanismos cobrem confidencialidade, integridade, disponibilidade, autenticação e autorização em escala acadêmica. HTTPS local usa certificado autoassinado, cuja confiança precisa ser aceita no navegador. A matriz não representa auditoria de produção ou certificação jurídica.
