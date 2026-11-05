import { ErroHttp } from './erros.js';

/**
 * Limitador simples em memória (janela fixa por IP) para dificultar força bruta no login.
 * Em produção com várias instâncias, prefira um armazenamento compartilhado (ex.: Redis).
 */
export function limitarTentativas({ maximo, janelaMs }) {
  const contagens = new Map();
  const limpeza = setInterval(() => {
    const agora = Date.now();
    for (const [chave, c] of contagens) if (c.expiraEm <= agora) contagens.delete(chave);
  }, janelaMs);
  limpeza.unref();

  return (req, res, next) => {
    const agora = Date.now();
    let c = contagens.get(req.ip);
    if (!c || c.expiraEm <= agora) {
      c = { total: 0, expiraEm: agora + janelaMs };
      contagens.set(req.ip, c);
    }
    c.total++;
    if (c.total > maximo) {
      res.set('Retry-After', String(Math.ceil((c.expiraEm - agora) / 1000)));
      return next(new ErroHttp(429, 'Muitas tentativas de login. Tente novamente mais tarde.'));
    }
    return next();
  };
}
