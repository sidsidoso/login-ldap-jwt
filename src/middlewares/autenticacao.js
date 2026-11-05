import { ErroHttp } from './erros.js';

/** Exige "Authorization: Bearer <jwt>" válido e popula req.usuario. */
export function exigirToken(servicoTokens) {
  return (req, res, next) => {
    const [esquema, token] = (req.get('authorization') ?? '').split(' ');
    if (esquema !== 'Bearer' || !token) {
      res.set('WWW-Authenticate', 'Bearer');
      return next(new ErroHttp(401, 'Token ausente'));
    }
    try {
      req.usuario = servicoTokens.verificar(token);
      return next();
    } catch (err) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      const msg = err.name === 'TokenExpiredError' ? 'Token expirado' : 'Token inválido';
      return next(new ErroHttp(401, msg));
    }
  };
}

/** Autoriza se o usuário tiver pelo menos um dos papéis informados. */
export function exigirPapel(...papeis) {
  return (req, res, next) => {
    const doUsuario = req.usuario?.papeis ?? [];
    if (papeis.some((p) => doUsuario.includes(p))) return next();
    return next(new ErroHttp(403, 'Acesso negado para o seu perfil'));
  };
}
