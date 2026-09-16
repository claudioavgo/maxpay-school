import { afterEach, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { freshApp } from "./helpers.js";
import { ask } from "../src/ai/assistant.js";
import { config } from "../src/config.js";

let app: FastifyInstance;
afterEach(async () => { vi.unstubAllGlobals(); await app?.close(); });

it("usa DeepSeek com contexto restrito e filtra CPF da resposta", async () => {
  app = await freshApp();
  config.deepseekApiKey = "test-key";
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ choices: [{ message: { content: "Seu CPF: 123.456.789-00" } }] })));
  vi.stubGlobal("fetch", fetchMock);
  const result = await ask(3, "Resuma meus gastos", "127.0.0.1");
  expect(result.provider).toBe("deepseek");
  expect(result.answer).toBe("Seu CPF: [CPF removido]");
  const [url, options] = fetchMock.mock.calls[0];
  expect(url).toBe("https://api.deepseek.com/chat/completions");
  const body = JSON.parse(options.body);
  expect(body.model).toBe("deepseek-flash");
  expect(body.messages[0].role).toBe("system");
  expect(body.messages[1].content).toContain("<transacoes>");
  expect(body.messages[1].content).not.toContain("cpf=");
});

it("retorna erro claro quando o provedor falha", async () => {
  app = await freshApp();
  config.deepseekApiKey = "test-key";
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("provider details", { status: 429 })));
  await expect(ask(3, "Resumo", "127.0.0.1")).rejects.toMatchObject({ statusCode: 503, message: "O assistente está indisponível no momento. Tente novamente." });
});

it("mantém a conversa do cliente e não mistura históricos", async () => {
  app = await freshApp();
  config.deepseekApiKey = "test-key";
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ choices: [{ message: { content: "Resumo inicial." } }] })));
  vi.stubGlobal("fetch", fetchMock);
  await ask(4, "Mensagem privada de Bruno", "127.0.0.1");
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ choices: [{ message: { content: "Você gastou em mercado." } }] })));
  await ask(3, "Em que gastei?", "127.0.0.1");
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ choices: [{ message: { content: "Esse foi o maior gasto." } }] })));
  await ask(3, "E qual foi o maior?", "127.0.0.1");
  const body = JSON.parse(fetchMock.mock.calls[2][1].body);
  expect(body.messages[1]).toEqual({ role: "user", content: "Em que gastei?" });
  expect(body.messages[2]).toEqual({ role: "assistant", content: "Você gastou em mercado." });
  expect(body.messages[3].content).toContain("E qual foi o maior?");
  expect(JSON.stringify(body)).not.toContain("Mensagem privada de Bruno");
});

it("identifica a primeira transação fora do recorte recente e exclui pendências dos totais", async () => {
  app = await freshApp();
  const { transactionsForAccount, recordTransaction } = await import("../src/accounts/service.js");
  const before = transactionsForAccount(1);
  const oldest = [...before].sort((a,b) => Date.parse(a.created_at) - Date.parse(b.created_at) || a.id - b.id)[0];
  const received = before.filter(t => t.to_account_id === 1 && t.status === "completed").reduce((sum,t) => sum + t.amount_cents, 0);
  for (let i = 0; i < 101; i++) {
    recordTransaction({ from: null, to: 1, amountCents: 10000, description: "Depósito com comprovante", status: "flagged", fundsMoved: false });
  }
  config.deepseekApiKey = "test-key";
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ choices: [{ message: { content: "Sua primeira transação foi o depósito inicial." } }] })));
  vi.stubGlobal("fetch", fetchMock);
  await ask(3, "Qual foi minha primeira transação?", "127.0.0.1");
  const body = JSON.parse(fetchMock.mock.calls[0][1].body);
  const context = JSON.parse(body.messages.at(-1).content.split("<transacoes>\n")[1].split("\n</transacoes>")[0]);
  expect(context.primeira_transacao.id).toBe(oldest.id);
  expect(context.primeiro_deposito.id).toBe(oldest.id);
  expect(context.ultima_transacao.status).toBe("em análise, sem conclusão");
  expect(context.lista_parcial).toBe(true);
  expect(context.transacoes).toHaveLength(100);
  expect(context.transacoes[0].id).toBeLessThan(context.transacoes.at(-1).id);
  expect(context.transacoes.some((t: {id:number}) => t.id === oldest.id)).toBe(false);
  expect(context.totais_concluidos.recebido).toBe((received / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" }));
});
