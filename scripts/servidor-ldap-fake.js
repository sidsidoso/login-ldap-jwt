// Servidor LDAP em memória (ldapjs) para demo e testes.
// NÃO use em produção: senhas ficam em memória e não há TLS.
import { timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import ldap from 'ldapjs';

export const BASE_DN = 'dc=empresa,dc=local';
export const CONTA_SERVICO = { dn: `cn=svc-login,ou=servicos,${BASE_DN}`, senha: 'svc-demo-123' };

const grupo = (cn) => `cn=${cn},ou=grupos,${BASE_DN}`;
const dnUsuario = (uid) => `uid=${uid},ou=usuarios,${BASE_DN}`;

// Usuários de exemplo (senhas apenas para demonstração)
export const USUARIOS_EXEMPLO = [
  { uid: 'ana.souza', nome: 'Ana Souza', senha: 'Ana@2026', grupos: ['ti-admins', 'colaboradores'] },
  { uid: 'bruno.lima', nome: 'Bruno Lima', senha: 'Bruno@2026', grupos: ['financeiro', 'colaboradores'] },
  { uid: 'carla.mendes', nome: 'Carla Mendes', senha: 'Carla@2026', grupos: ['colaboradores'] }
];

function montarEntradas() {
  const entradas = [{
    dn: CONTA_SERVICO.dn,
    attributes: { objectClass: ['top', 'applicationProcess'], cn: 'svc-login' }
  }];
  const senhas = new Map([[CONTA_SERVICO.dn, CONTA_SERVICO.senha]]);

  for (const u of USUARIOS_EXEMPLO) {
    senhas.set(dnUsuario(u.uid), u.senha);
    entradas.push({
      dn: dnUsuario(u.uid),
      attributes: {
        objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
        uid: u.uid,
        sAMAccountName: u.uid,
        cn: u.nome,
        mail: `${u.uid}@empresa.local`,
        memberOf: u.grupos.map(grupo)
      }
    });
  }

  for (const cn of new Set(USUARIOS_EXEMPLO.flatMap((u) => u.grupos))) {
    entradas.push({
      dn: grupo(cn),
      attributes: {
        objectClass: ['top', 'groupOfNames'],
        cn,
        member: USUARIOS_EXEMPLO.filter((u) => u.grupos.includes(cn)).map((u) => dnUsuario(u.uid))
      }
    });
  }
  return { entradas, senhas };
}

const normalizarDn = (dn) => String(dn).replace(/\s*,\s*/g, ',').toLowerCase();

// Cópia com nomes e valores em minúsculas: simula a comparação sem distinção de caixa do LDAP real
const minusculas = (attrs) => Object.fromEntries(Object.entries(attrs).map(([k, v]) => [
  k.toLowerCase(), [v].flat().map((x) => x.toLowerCase())
]));

/** Converte "\2a", "\c3\a1"... (RFC 4515) de volta para texto. */
function desescapar(valor) {
  const bytes = Buffer.from(String(valor ?? ''), 'utf8');
  const saida = [];
  for (let i = 0; i < bytes.length; i++) {
    const hex = bytes.subarray(i + 1, i + 3).toString('latin1');
    if (bytes[i] === 0x5c && /^[0-9a-f]{2}$/i.test(hex)) {
      saida.push(Number.parseInt(hex, 16));
      i += 2;
    } else {
      saida.push(bytes[i]);
    }
  }
  return Buffer.from(saida).toString('utf8').toLowerCase();
}

const escaparRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Avalia o filtro recebido. O matches() do ldapjs compara os valores ainda escapados,
 * por isso o servidor fake usa este avaliador próprio (and/or/not/=/substring/presença).
 */
function casa(filtro, attrs) {
  const valores = attrs[filtro.attribute?.toLowerCase()] ?? [];
  switch (filtro.type) {
    case 'AndFilter': return filtro.clauses.every((f) => casa(f, attrs));
    case 'OrFilter': return filtro.clauses.some((f) => casa(f, attrs));
    case 'NotFilter': return !casa(filtro.filter, attrs);
    case 'PresenceFilter': return valores.length > 0;
    case 'EqualityFilter': return valores.includes(desescapar(filtro.value));
    case 'SubstringFilter': {
      const partes = [filtro.initial ?? '', ...filtro.any, filtro.final ?? ''].map((p) => escaparRegex(desescapar(p)));
      return valores.some((v) => new RegExp(`^${partes.join('.*')}$`, 's').test(v));
    }
    default: return false;
  }
}

function senhaConfere(esperada, recebida) {
  const a = Buffer.from(String(esperada));
  const b = Buffer.from(String(recebida));
  return a.length === b.length && timingSafeEqual(a, b);
}

function dentroDoEscopo(dnEntrada, dnBase, escopo) {
  if (escopo === 'base') return dnEntrada === dnBase;
  if (dnEntrada !== dnBase && !dnEntrada.endsWith(`,${dnBase}`)) return false;
  if (escopo === 'single') return dnEntrada.split(',').length === dnBase.split(',').length + 1;
  return true; // subtree
}

/**
 * Sobe o servidor LDAP fake.
 * @returns {Promise<{ url: string, fechar: () => Promise<void> }>}
 */
export function iniciarServidorLdapFake({ porta = 0, host = '127.0.0.1' } = {}) {
  const { entradas, senhas } = montarEntradas();
  const indice = entradas.map((e) => ({ ...e, dnNorm: normalizarDn(e.dn), busca: minusculas(e.attributes) }));
  const senhasNorm = new Map([...senhas].map(([dn, s]) => [normalizarDn(dn), s]));
  const servidor = ldap.createServer();

  servidor.bind(BASE_DN, (req, res, next) => {
    const esperada = senhasNorm.get(normalizarDn(req.dn.toString()));
    if (esperada === undefined || !senhaConfere(esperada, req.credentials)) {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  // Exige bind autenticado antes de qualquer busca
  const exigirBind = (req, res, next) => {
    const quem = normalizarDn(req.connection.ldap.bindDN.toString());
    if (!senhasNorm.has(quem)) return next(new ldap.InsufficientAccessRightsError());
    return next();
  };

  servidor.search(BASE_DN, exigirBind, (req, res, next) => {
    const base = normalizarDn(req.dn.toString());
    const limite = req.sizeLimit > 0 ? req.sizeLimit : Infinity;
    let enviados = 0;
    // O ldapjs compara os atributos pedidos em minúsculas (nomes LDAP não diferenciam caixa)
    res.attributes = res.attributes.map((a) => a.toLowerCase());
    for (const e of indice) {
      if (enviados >= limite) break;
      if (!dentroDoEscopo(e.dnNorm, base, req.scopeName)) continue;
      if (casa(req.filter, e.busca)) {
        // res.send altera o objeto recebido; por isso enviamos uma cópia
        res.send({ dn: e.dn, attributes: structuredClone(e.attributes) });
        enviados++;
      }
    }
    res.end();
    return next();
  });

  return new Promise((resolve, reject) => {
    servidor.once('error', reject);
    servidor.listen(porta, host, () => {
      resolve({
        url: `ldap://${host}:${servidor.port}`,
        fechar: () => new Promise((r) => servidor.close(() => r()))
      });
    });
  });
}

// Execução direta: npm run ldap:fake
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const porta = Number(process.env.LDAP_FAKE_PORTA ?? 1389);
  const { url } = await iniciarServidorLdapFake({ porta });
  console.log(`Servidor LDAP fake ouvindo em ${url} (base ${BASE_DN})`);
  console.log(`Conta de serviço: ${CONTA_SERVICO.dn}`);
  console.log(`Usuários de exemplo: ${USUARIOS_EXEMPLO.map((u) => u.uid).join(', ')}`);
}
