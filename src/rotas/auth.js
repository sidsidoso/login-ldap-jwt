import { Router } from 'express';
import { ErroHttp } from '../middlewares/erros.js';

const USUARIO_VALIDO = /^[A-Za-z0-9._@-]{1,64}$/;

export function rotasAuth({ servicoAuth, servicoTokens, expiraEm, limitador }) {
  const router = Router();

  router.post('/login', limitador, async (req, res) => {
    const { usuario, senha } = req.body ?? {};
    if (typeof usuario !== 'string' || !USUARIO_VALIDO.test(usuario)) {
      throw new ErroHttp(400, 'Campo "usuario" inválido');
    }
    // Senha vazia faria um "bind não autenticado", aceito por muitos servidores LDAP
    if (typeof senha !== 'string' || senha.length === 0 || senha.length > 256) {
      throw new ErroHttp(400, 'Campo "senha" inválido');
    }

    const perfil = await servicoAuth.autenticar(usuario, senha);
    const token = servicoTokens.emitir(perfil);
    res.json({ token, tipo: 'Bearer', expiraEm, usuario: perfil });
  });

  return router;
}
