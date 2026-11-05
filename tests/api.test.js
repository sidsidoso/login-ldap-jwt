import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, describe, it } from 'node:test';
import jwt from 'jsonwebtoken';
import { CONTA_SERVICO, iniciarServidorLdapFake } from '../scripts/servidor-ldap-fake.js';
import { criarApp } from '../src/app.js';
import { carregarConfig } from '../src/config.js';
import { criarServicoAutenticacao } from '../src/servicos/autenticacao.js';

const SEGREDO = 'segredo-de-teste-com-mais-de-32-caracteres';

async function subirApi(config) {
  const servidor = criarApp(config).listen(0, '127.0.0.1');
  await once(servidor, 'listening');
  return { servidor, base: `http://127.0.0.1:${servidor.address().port}` };
}

const login = (base, usuario, senha) => fetch(`${base}/auth/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ usuario, senha })
});

describe('API de login LDAP + JWT', () => {
  let ldap, api, config;

  before(async () => {
    ldap = await iniciarServidorLdapFake({ porta: 0 });
    config = carregarConfig({
      LDAP_URL: ldap.url,
      LDAP_BIND_DN: CONTA_SERVICO.dn,
      LDAP_BIND_SENHA: CONTA_SERVICO.senha,
      LDAP_TIMEOUT_MS: '2000',
      JWT_SEGREDO: SEGREDO,
      LOGIN_MAX_TENTATIVAS: '100'
    });
    api = await subirApi(config);
  });

  after(async () => {
    api.servidor.close();
    await ldap.fechar();
  });

  it('GET /saude responde ok', async () => {
    const res = await fetch(`${api.base}/saude`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-powered-by'), null);
    assert.deepEqual(await res.json(), { status: 'ok' });
  });

  it('login válido devolve JWT com papéis mapeados dos grupos', async () => {
    const res = await login(api.base, 'ana.souza', 'Ana@2026');
    assert.equal(res.status, 200);
    const corpo = await res.json();
    assert.equal(corpo.tipo, 'Bearer');
    assert.deepEqual(corpo.usuario.papeis, ['admin', 'usuario']);
    assert.deepEqual(corpo.usuario.grupos, ['ti-admins', 'colaboradores']);

    const { header, payload } = jwt.decode(corpo.token, { complete: true });
    assert.equal(header.alg, 'HS256');
    assert.equal(payload.sub, 'ana.souza');
    assert.equal(payload.iss, 'login-ldap-jwt');
    assert.ok(payload.exp - payload.iat <= 15 * 60, 'expiração curta');
  });

  it('senha errada e usuário inexistente recebem a mesma resposta 401', async () => {
    const r1 = await login(api.base, 'ana.souza', 'errada');
    const r2 = await login(api.base, 'nao.existe', 'qualquer');
    assert.equal(r1.status, 401);
    assert.equal(r2.status, 401);
    assert.deepEqual(await r1.json(), await r2.json());
  });

  it('tentativa de LDAP injection no usuário é recusada', async () => {
    // "*" passaria a casar com todos os usuários se o filtro não fosse escapado
    const res = await login(api.base, '*', 'Ana@2026');
    assert.equal(res.status, 400);
    const res2 = await fetch(`${api.base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ usuario: 'ana.souza)(uid=*', senha: 'x' })
    });
    assert.equal(res2.status, 400);
  });

  it('o serviço escapa o filtro mesmo sem a validação da rota', async () => {
    const servico = criarServicoAutenticacao(config);
    // Sem escape, "*" casaria com todos os usuários; escapado, não casa com nenhum
    await assert.rejects(servico.autenticar('*', 'Ana@2026'), { status: 401 });
    await assert.rejects(servico.autenticar('ana*', 'Ana@2026'), { status: 401 });
    const perfil = await servico.autenticar('ana.souza', 'Ana@2026');
    assert.equal(perfil.nome, 'Ana Souza');
  });

  it('senha vazia é rejeitada antes de chegar ao LDAP', async () => {
    const res = await login(api.base, 'ana.souza', '');
    assert.equal(res.status, 400);
  });

  it('JSON malformado gera 400 em JSON', async () => {
    const res = await fetch(`${api.base}/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"usuario":'
    });
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { erro: 'JSON inválido' });
  });

  it('GET /me exige token e devolve o perfil', async () => {
    assert.equal((await fetch(`${api.base}/me`)).status, 401);

    const { token } = await (await login(api.base, 'bruno.lima', 'Bruno@2026')).json();
    const res = await fetch(`${api.base}/me`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    const me = await res.json();
    assert.equal(me.usuario, 'bruno.lima');
    assert.equal(me.email, 'bruno.lima@empresa.local');
    assert.deepEqual(me.papeis, ['financeiro', 'usuario']);
  });

  it('autorização por papel: 403 sem o papel, 200 com o papel', async () => {
    const { token: tokenCarla } = await (await login(api.base, 'carla.mendes', 'Carla@2026')).json();
    const { token: tokenAna } = await (await login(api.base, 'ana.souza', 'Ana@2026')).json();
    const { token: tokenBruno } = await (await login(api.base, 'bruno.lima', 'Bruno@2026')).json();
    const get = (rota, token) => fetch(`${api.base}${rota}`, { headers: { authorization: `Bearer ${token}` } });

    assert.equal((await get('/admin/painel', tokenCarla)).status, 403);
    assert.equal((await get('/admin/painel', tokenAna)).status, 200);
    assert.equal((await get('/financeiro/relatorios', tokenBruno)).status, 200);
    assert.equal((await get('/financeiro/relatorios', tokenAna)).status, 200);
    assert.equal((await get('/financeiro/relatorios', tokenCarla)).status, 403);
  });

  it('token expirado ou com "alg: none" é rejeitado', async () => {
    const opcoes = { subject: 'ana.souza', issuer: 'login-ldap-jwt', audience: 'apis-internas' };
    const expirado = jwt.sign({ papeis: ['admin'], exp: Math.floor(Date.now() / 1000) - 10 }, SEGREDO, opcoes);
    const semAssinatura = jwt.sign({ papeis: ['admin'] }, null, { ...opcoes, algorithm: 'none' });

    const r1 = await fetch(`${api.base}/me`, { headers: { authorization: `Bearer ${expirado}` } });
    assert.equal(r1.status, 401);
    assert.deepEqual(await r1.json(), { erro: 'Token expirado' });
    const r2 = await fetch(`${api.base}/admin/painel`, { headers: { authorization: `Bearer ${semAssinatura}` } });
    assert.equal(r2.status, 401);
  });

  it('rota inexistente devolve 404 em JSON', async () => {
    const res = await fetch(`${api.base}/nao-existe`);
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { erro: 'Rota não encontrada' });
  });

  it('LDAP fora do ar devolve 503', async () => {
    const off = await subirApi({ ...config, ldap: { ...config.ldap, url: 'ldap://127.0.0.1:1', timeoutMs: 1000 } });
    try {
      const res = await login(off.base, 'ana.souza', 'Ana@2026');
      assert.equal(res.status, 503);
    } finally {
      off.servidor.close();
    }
  });

  it('limita tentativas de login por IP (429)', async () => {
    const lim = await subirApi({ ...config, limiteLogin: { maximo: 2, janelaMs: 60_000 } });
    try {
      await login(lim.base, 'ana.souza', 'errada');
      await login(lim.base, 'ana.souza', 'errada');
      const res = await login(lim.base, 'ana.souza', 'Ana@2026');
      assert.equal(res.status, 429);
      assert.ok(Number(res.headers.get('retry-after')) > 0);
    } finally {
      lim.servidor.close();
    }
  });
});
