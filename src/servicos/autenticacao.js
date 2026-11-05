// Autenticação em duas etapas: a conta de serviço localiza o DN; o bind com a senha do usuário valida.
import { bind, buscar, conectar, encerrar, escaparFiltro, InvalidCredentialsError } from './ldap.js';
import { ErroHttp } from '../middlewares/erros.js';

const credenciaisInvalidas = () => new ErroHttp(401, 'Usuário ou senha inválidos');

/** Extrai o CN de um DN de grupo: "cn=ti-admins,ou=grupos,..." -> "ti-admins" */
export function cnDoGrupo(dn) {
  const m = /^cn=((?:\\.|[^,])+)/i.exec(String(dn).trim());
  return m ? m[1].replace(/\\(.)/g, '$1').toLowerCase() : null;
}

export function mapearPapeis(gruposDn, mapaPapeis) {
  const papeis = new Set();
  for (const dn of gruposDn) {
    const papel = mapaPapeis[cnDoGrupo(dn)];
    if (papel) papeis.add(papel);
  }
  return [...papeis].sort();
}

export function criarServicoAutenticacao({ ldap: cfg, mapaPapeis }) {
  return {
    async autenticar(usuario, senha) {
      const cliente = await conectar(cfg);
      try {
        try {
          await bind(cliente, cfg.bindDn, cfg.bindSenha);
        } catch {
          throw new ErroHttp(503, 'Falha ao autenticar a conta de serviço no LDAP');
        }

        const entradas = await buscar(cliente, cfg.baseUsuarios, {
          scope: 'sub',
          filter: `(&(objectClass=person)(${cfg.atributoLogin}=${escaparFiltro(usuario)}))`,
          attributes: ['cn', 'mail', 'memberOf', cfg.atributoLogin],
          sizeLimit: 2,
          timeLimit: Math.ceil(cfg.timeoutMs / 1000)
        });
        // Nenhum ou mais de um resultado: recusa sem revelar o motivo
        if (entradas.length !== 1) throw credenciaisInvalidas();
        const [entrada] = entradas;

        // Reaproveita a mesma conexão: o rebind troca a identidade para a do usuário
        try {
          await bind(cliente, entrada.dn, senha);
        } catch (err) {
          if (err instanceof InvalidCredentialsError) throw credenciaisInvalidas();
          throw err;
        }

        const grupos = entrada.memberOf ?? [];
        return {
          usuario: entrada[cfg.atributoLogin]?.[0] ?? usuario,
          nome: entrada.cn?.[0] ?? usuario,
          email: entrada.mail?.[0] ?? null,
          grupos: grupos.map(cnDoGrupo).filter(Boolean),
          papeis: mapearPapeis(grupos, mapaPapeis)
        };
      } finally {
        await encerrar(cliente);
      }
    }
  };
}
