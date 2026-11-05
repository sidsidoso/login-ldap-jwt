// Helpers finos sobre o cliente ldapjs, expostos como Promises
import ldap from 'ldapjs';
import { ErroHttp } from '../middlewares/erros.js';

/** Escapa um valor para uso em filtro LDAP (RFC 4515), evitando LDAP injection. */
export function escaparFiltro(valor) {
  return String(valor).replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

/** Abre uma conexão e aguarda o evento "connect" (com timeout). */
export function conectar({ url, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const cliente = ldap.createClient({ url, timeout: timeoutMs, connectTimeout: timeoutMs });
    // Sem listener, um erro de socket derrubaria o processo
    cliente.on('error', () => {});
    const falhar = () => {
      cliente.destroy();
      reject(new ErroHttp(503, 'Serviço de diretório indisponível'));
    };
    cliente.once('connectError', falhar);
    cliente.once('connectTimeout', falhar);
    cliente.once('connect', () => {
      cliente.removeListener('connectError', falhar);
      cliente.removeListener('connectTimeout', falhar);
      resolve(cliente);
    });
  });
}

export function bind(cliente, dn, senha) {
  return new Promise((resolve, reject) => {
    cliente.bind(dn, senha, (err) => (err ? reject(err) : resolve()));
  });
}

/** Busca e devolve entradas como objetos simples: { dn, atributo: [valores] }. */
export function buscar(cliente, base, opcoes) {
  return new Promise((resolve, reject) => {
    cliente.search(base, opcoes, (err, res) => {
      if (err) return reject(err);
      const entradas = [];
      res.on('searchEntry', (entrada) => {
        const { objectName, attributes } = entrada.pojo;
        const obj = { dn: objectName };
        for (const { type, values } of attributes) obj[type] = values;
        entradas.push(obj);
      });
      res.on('error', reject);
      res.on('end', () => resolve(entradas));
    });
  });
}

/** Encerra a sessão (unbind) e garante o fechamento do socket. */
export function encerrar(cliente) {
  return new Promise((resolve) => {
    cliente.unbind(() => {
      cliente.destroy();
      resolve();
    });
  });
}

export const { InvalidCredentialsError } = ldap;
