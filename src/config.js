// Configuração lida de variáveis de ambiente (padrões pensados para desenvolvimento)
const inteiro = (valor, padrao) => {
  const n = Number.parseInt(valor ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : padrao;
};

// Mapa "CN do grupo" -> "papel"
function lerMapaPapeis(texto) {
  if (!texto) return { 'ti-admins': 'admin', financeiro: 'financeiro', colaboradores: 'usuario' };
  try {
    const mapa = JSON.parse(texto);
    return Object.fromEntries(Object.entries(mapa).map(([g, p]) => [g.toLowerCase(), String(p)]));
  } catch {
    throw new Error('MAPA_PAPEIS deve ser um JSON válido, ex.: {"ti-admins":"admin"}');
  }
}

export function carregarConfig(env = process.env) {
  return {
    porta: inteiro(env.PORTA, 3000),
    ldap: {
      url: env.LDAP_URL ?? 'ldap://127.0.0.1:1389',
      baseUsuarios: env.LDAP_BASE_USUARIOS ?? 'ou=usuarios,dc=empresa,dc=local',
      bindDn: env.LDAP_BIND_DN ?? 'cn=svc-login,ou=servicos,dc=empresa,dc=local',
      bindSenha: env.LDAP_BIND_SENHA ?? '',
      atributoLogin: env.LDAP_ATRIBUTO_LOGIN ?? 'uid', // no Active Directory: sAMAccountName
      timeoutMs: inteiro(env.LDAP_TIMEOUT_MS, 5000)
    },
    jwt: {
      segredo: env.JWT_SEGREDO ?? '',
      expiraEm: env.JWT_EXPIRA_EM ?? '15m',
      emissor: env.JWT_EMISSOR ?? 'login-ldap-jwt',
      audiencia: env.JWT_AUDIENCIA ?? 'apis-internas'
    },
    mapaPapeis: lerMapaPapeis(env.MAPA_PAPEIS),
    limiteLogin: {
      maximo: inteiro(env.LOGIN_MAX_TENTATIVAS, 10),
      janelaMs: inteiro(env.LOGIN_JANELA_MS, 15 * 60_000)
    }
  };
}

export function validarConfig(config) {
  if (config.jwt.segredo.length < 32) throw new Error('JWT_SEGREDO precisa ter pelo menos 32 caracteres');
  if (!config.ldap.bindSenha) throw new Error('LDAP_BIND_SENHA não definida');
  if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(config.ldap.atributoLogin)) throw new Error('LDAP_ATRIBUTO_LOGIN inválido');
  return config;
}
