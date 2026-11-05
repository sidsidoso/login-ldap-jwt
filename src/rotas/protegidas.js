import { Router } from 'express';
import { exigirPapel, exigirToken } from '../middlewares/autenticacao.js';

export function rotasProtegidas({ servicoTokens }) {
  const router = Router();
  const autenticado = exigirToken(servicoTokens);

  // Dados do usuário autenticado, extraídos do próprio token (sem nova ida ao LDAP)
  router.get('/me', autenticado, (req, res) => {
    const { sub, nome, email, papeis, exp } = req.usuario;
    res.json({ usuario: sub, nome, email, papeis, expiraEm: new Date(exp * 1000).toISOString() });
  });

  router.get('/admin/painel', autenticado, exigirPapel('admin'), (req, res) => {
    res.json({ mensagem: `Bem-vindo(a) ao painel administrativo, ${req.usuario.nome}` });
  });

  router.get('/financeiro/relatorios', autenticado, exigirPapel('financeiro', 'admin'), (req, res) => {
    res.json({ relatorios: ['fluxo-de-caixa-2026-10', 'despesas-2026-10'] });
  });

  return router;
}
