import express from 'express';
import { naoEncontrado, tratadorErros } from './middlewares/erros.js';
import { limitarTentativas } from './middlewares/limiteTentativas.js';
import { rotasAuth } from './rotas/auth.js';
import { rotasProtegidas } from './rotas/protegidas.js';
import { criarServicoAutenticacao } from './servicos/autenticacao.js';
import { criarServicoTokens } from './servicos/tokens.js';

/**
 * Monta a aplicação. Os serviços podem ser injetados (útil nos testes).
 */
export function criarApp(config, {
  servicoAuth = criarServicoAutenticacao(config),
  servicoTokens = criarServicoTokens(config.jwt)
} = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));

  const limitador = limitarTentativas(config.limiteLogin ?? { maximo: 10, janelaMs: 15 * 60_000 });

  app.get('/saude', (req, res) => res.json({ status: 'ok' }));
  app.use('/auth', rotasAuth({ servicoAuth, servicoTokens, expiraEm: config.jwt.expiraEm, limitador }));
  app.use(rotasProtegidas({ servicoTokens }));

  app.use(naoEncontrado);
  app.use(tratadorErros);
  return app;
}
