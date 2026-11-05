import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import jwt from 'jsonwebtoken';
import { cnDoGrupo, mapearPapeis } from '../src/servicos/autenticacao.js';
import { escaparFiltro } from '../src/servicos/ldap.js';
import { criarServicoTokens } from '../src/servicos/tokens.js';

describe('escaparFiltro (RFC 4515)', () => {
  it('escapa os caracteres especiais de filtro', () => {
    assert.equal(escaparFiltro('*'), '\\2a');
    assert.equal(escaparFiltro('a(b)c'), 'a\\28b\\29c');
    assert.equal(escaparFiltro('x\\y'), 'x\\5cy');
    assert.equal(escaparFiltro('nul\0'), 'nul\\00');
  });

  it('neutraliza tentativa de injeção', () => {
    assert.equal(escaparFiltro('*)(uid=*'), '\\2a\\29\\28uid=\\2a');
  });

  it('mantém valores comuns intactos', () => {
    assert.equal(escaparFiltro('ana.souza'), 'ana.souza');
  });
});

describe('grupos e papéis', () => {
  it('extrai o CN do DN do grupo', () => {
    assert.equal(cnDoGrupo('cn=TI-Admins,ou=grupos,dc=empresa,dc=local'), 'ti-admins');
    assert.equal(cnDoGrupo('cn=Vendas\\, Sul,ou=grupos'), 'vendas, sul');
    assert.equal(cnDoGrupo('ou=grupos'), null);
  });

  it('mapeia grupos para papéis sem duplicar', () => {
    const papeis = mapearPapeis(
      ['cn=ti-admins,ou=g', 'cn=colaboradores,ou=g', 'cn=desconhecido,ou=g'],
      { 'ti-admins': 'admin', colaboradores: 'usuario' }
    );
    assert.deepEqual(papeis, ['admin', 'usuario']);
  });
});

describe('servico de tokens', () => {
  const cfg = { segredo: 'x'.repeat(32), expiraEm: '5m', emissor: 'teste', audiencia: 'apis' };
  const tokens = criarServicoTokens(cfg);

  it('emite e verifica um JWT HS256', () => {
    const token = tokens.emitir({ usuario: 'ana', nome: 'Ana', email: null, papeis: ['admin'] });
    const dados = tokens.verificar(token);
    assert.equal(dados.sub, 'ana');
    assert.deepEqual(dados.papeis, ['admin']);
    assert.equal(jwt.decode(token, { complete: true }).header.alg, 'HS256');
  });

  it('rejeita token com alg "none"', () => {
    const semAssinatura = jwt.sign({ papeis: ['admin'] }, null, {
      algorithm: 'none', subject: 'intruso', issuer: 'teste', audience: 'apis'
    });
    assert.throws(() => tokens.verificar(semAssinatura));
  });

  it('rejeita token assinado com outro segredo', () => {
    const outro = jwt.sign({}, 'y'.repeat(32), { subject: 'x', issuer: 'teste', audience: 'apis' });
    assert.throws(() => tokens.verificar(outro), { name: 'JsonWebTokenError' });
  });
});
