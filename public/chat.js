const form = document.querySelector('#chat-form');
const input = document.querySelector('#chat-question');
const send = document.querySelector('#chat-send');
const messages = document.querySelector('#chat-messages');
const error = document.querySelector('#chat-error');
let sending = false;

// Build formatting with text nodes: model output is never interpreted as HTML.
function formatAnswer(element, text) {
  element.replaceChildren();
  for (const part of text.split(/(\*\*[^*]+\*\*)/g)) {
    if (part.startsWith('**') && part.endsWith('**')) {
      const strong = document.createElement('strong');
      strong.textContent = part.slice(2, -2);
      element.append(strong);
    } else {
      element.append(document.createTextNode(part));
    }
  }
}

function scrollToLatest() { messages.scrollTop = messages.scrollHeight; }
function updateComposer() {
  send.disabled = sending || !input.value.trim();
  input.style.height = 'auto';
  input.style.height = Math.min(input.scrollHeight, 130) + 'px';
}
function addMessage(role, text) {
  const message = document.createElement('article');
  message.className = `chat-message chat-message-${role}`;
  message.setAttribute('aria-label', role === 'user' ? 'Sua mensagem' : 'Resposta do assistente');
  const author = document.createElement('span');
  author.className = 'message-author';
  author.textContent = role === 'user' ? 'Você' : 'MaxPay';
  const body = document.createElement('div');
  body.className = 'message-text';
  if (role === 'assistant') formatAnswer(body, text);
  else body.textContent = text;
  message.append(author, body);
  messages.append(message);
  scrollToLatest();
  return message;
}

for (const answer of messages.querySelectorAll('.chat-message-assistant .message-text')) {
  formatAnswer(answer, answer.textContent);
}
scrollToLatest();
updateComposer();
input.addEventListener('input', updateComposer);
input.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    if (!sending && input.value.trim()) form.requestSubmit();
  }
});
for (const suggestion of document.querySelectorAll('[data-question]')) {
  suggestion.addEventListener('click', () => {
    input.value = suggestion.dataset.question;
    updateComposer();
    form.requestSubmit();
  });
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const question = input.value.trim();
  if (sending || !question) return;
  sending = true;
  error.hidden = true;
  const welcome = document.querySelector('#chat-welcome');
  if (welcome) welcome.hidden = true;
  const userMessage = addMessage('user', question);
  const pending = addMessage('assistant', 'Pensando…');
  pending.classList.add('chat-pending');
  input.value = '';
  input.readOnly = true;
  updateComposer();
  try {
    const response = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    });
    if (!response.ok) {
      if (response.status === 401) throw new Error('Sua sessão expirou. Entre novamente para continuar.');
      if (response.status === 429) throw new Error('Você enviou várias mensagens. Aguarde um minuto e tente novamente.');
      throw new Error('Não consegui responder agora. Tente enviar novamente.');
    }
    const result = await response.json();
    if (typeof result.answer !== 'string' || !result.answer.trim()) throw new Error('Não consegui responder agora. Tente enviar novamente.');
    pending.classList.remove('chat-pending');
    formatAnswer(pending.querySelector('.message-text'), result.answer);
    welcome?.remove();
    scrollToLatest();
  } catch (failure) {
    pending.remove();
    userMessage.remove();
    if (welcome) welcome.hidden = false;
    input.value = question;
    error.textContent = failure instanceof TypeError ? 'Não foi possível conectar. Confira sua conexão e tente novamente.' : failure.message;
    error.hidden = false;
  } finally {
    sending = false;
    input.readOnly = false;
    updateComposer();
    input.focus();
  }
});
