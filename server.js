require('dotenv').config();

const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const rootDir = __dirname;
const isProduction = process.env.NODE_ENV === 'production';
const allowedServiceInterests = new Set([
  'Blindagem',
  'Reparo e manutencao',
  'Acessorios',
  'Vistoria e laudo',
  'Atendimento comercial',
  'Consulta geral',
]);
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 5;

app.disable('x-powered-by');
app.use((request, response, next) => {
  response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  if (isProduction) {
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
});
app.use(express.json({ limit: '20kb' }));
app.use(express.static(rootDir));

app.post('/api/contact', async (request, response) => {
  if (!request.is('application/json')) {
    return response.status(415).json({
      ok: false,
      message: 'Formato de envio inválido.',
    });
  }

  const ip = getClientIp(request);

  if (!isRateLimitAllowed(ip)) {
    return response.status(429).json({
      ok: false,
      message: 'Muitas tentativas em pouco tempo. Tente novamente em alguns minutos.',
    });
  }

  const validation = validateContactPayload(request.body || {});

  if (!validation.ok) {
    return response.status(400).json({
      ok: false,
      fieldErrors: validation.fieldErrors,
      message: 'Revise os campos destacados e tente novamente.',
    });
  }

  try {
    const delivery = await deliverContact(validation.data);

    return response.status(200).json({
      ok: true,
      message: 'Mensagem enviada com sucesso. Nossa equipe entrará em contato em breve.',
      deliveryMode: delivery.mode,
    });
  } catch (error) {
    console.error('Contact delivery failed:', error);

    return response.status(500).json({
      ok: false,
      message: 'Não foi possível enviar agora. Tente novamente em instantes.',
    });
  }
});

app.get('/', (_request, response) => {
  response.sendFile(path.join(rootDir, 'index.html'));
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`Shield Rio running at http://localhost:${port}`);
});

function getClientIp(request) {
  const forwardedFor = request.headers['x-forwarded-for'];

  if (typeof forwardedFor === 'string' && forwardedFor.length > 0) {
    return forwardedFor.split(',')[0].trim();
  }

  return request.socket.remoteAddress || 'unknown';
}

function isRateLimitAllowed(ip) {
  const now = Date.now();
  const stored = rateLimitStore.get(ip) || [];
  const recent = stored.filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);

  if (recent.length === 0) {
    rateLimitStore.delete(ip);
  }

  if (recent.length >= RATE_LIMIT_MAX_REQUESTS) {
    rateLimitStore.set(ip, recent);
    return false;
  }

  recent.push(now);
  rateLimitStore.set(ip, recent);
  return true;
}

function validateContactPayload(payload) {
  const fieldErrors = {};
  const data = {
    name: sanitizeText(payload.name),
    email: sanitizeEmail(payload.email),
    phone: sanitizeText(payload.phone),
    serviceInterest: sanitizeText(payload.serviceInterest),
    message: sanitizeMessage(payload.message),
    privacyConsent: payload.privacyConsent === true,
    honeypot: sanitizeText(payload.website),
  };

  if (!data.name) {
    fieldErrors.name = 'Informe seu nome completo.';
  }

  if (!data.email) {
    fieldErrors.email = 'Informe seu e-mail.';
  } else if (!isValidEmail(data.email)) {
    fieldErrors.email = 'Informe um e-mail válido.';
  }

  if (data.phone && !isValidPhone(data.phone)) {
    fieldErrors.phone = 'Informe um telefone válido ou deixe este campo em branco.';
  }

  if (data.serviceInterest && !allowedServiceInterests.has(data.serviceInterest)) {
    fieldErrors.serviceInterest = 'Selecione uma opção de consulta válida.';
  }

  if (!data.message) {
    fieldErrors.message = 'Escreva sua mensagem.';
  } else if (data.message.length > 3000) {
    fieldErrors.message = 'Sua mensagem esta muito longa. Tente resumir um pouco.';
  }

  if (!data.privacyConsent) {
    fieldErrors.privacyConsent = 'Você precisa aceitar a política de privacidade para continuar.';
  }

  if (data.honeypot) {
    fieldErrors.form = 'Não foi possível concluir o envio.';
  }

  return {
    ok: Object.keys(fieldErrors).length === 0,
    fieldErrors,
    data,
  };
}

function sanitizeText(value) {
  if (typeof value !== 'string') {
    return '';
  }

  return value.replace(/[\u0000-\u001F\u007F<>]/g, ' ').replace(/\s+/g, ' ').trim();
}

function sanitizeEmail(value) {
  return sanitizeText(value).toLowerCase();
}

function sanitizeMessage(value) {
  if (typeof value !== 'string') {
    return '';
  }

  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F<>]/g, ' ').replace(/\r\n/g, '\n').trim();
}

function isValidEmail(email) {
  if (email.length < 6 || email.length > 254) {
    return false;
  }

  if (email.includes('..')) {
    return false;
  }

  const parts = email.split('@');

  if (parts.length !== 2) {
    return false;
  }

  const [localPart, domain] = parts;

  if (!localPart || !domain || localPart.length > 64) {
    return false;
  }

  if (!domain.includes('.') || domain.startsWith('.') || domain.endsWith('.')) {
    return false;
  }

  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(email);
}

function isValidPhone(phone) {
  const digits = phone.replace(/\D/g, '');
  return digits.length >= 8 && digits.length <= 15;
}

async function deliverContact(data) {
  const deliveryMode = process.env.CONTACT_DELIVERY_MODE === 'smtp' ? 'smtp' : 'log';

  if (deliveryMode === 'smtp') {
    return sendWithSmtp(data);
  }

  console.log('Contact submission received (log mode):');
  console.log(formatSubmissionForLog(data));

  return { mode: 'log' };
}

async function sendWithSmtp(data) {
  const to = process.env.CONTACT_TO_EMAIL;
  const from = process.env.CONTACT_FROM_EMAIL;
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT) || 587;
  const secure = String(process.env.SMTP_SECURE).toLowerCase() === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!to || !from || !host || !user || !pass) {
    throw new Error('SMTP configuration is incomplete.');
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass,
    },
  });

  await transporter.sendMail({
    to,
    from,
    replyTo: data.email,
    subject: `[Shield Rio] ${data.serviceInterest || 'Consulta geral'} - ${data.name}`,
    text: formatSubmissionForLog(data),
  });

  return { mode: 'smtp' };
}

function formatSubmissionForLog(data) {
  return [
    `Nome: ${data.name}`,
    `E-mail: ${data.email}`,
    `Telefone: ${data.phone || 'Não informado'}`,
    `Tipo de consulta: ${data.serviceInterest || 'Não informado'}`,
    `Privacidade aceita: ${data.privacyConsent ? 'Sim' : 'Não'}`,
    '',
    'Mensagem:',
    data.message,
  ].join('\n');
}
