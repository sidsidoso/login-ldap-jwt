import jwt from 'jsonwebtoken';

const ALGORITMO = 'HS256';

export function criarServicoTokens({ segredo, expiraEm, emissor, audiencia }) {
  return {
    emitir({ usuario, nome, email, papeis }) {
      return jwt.sign({ nome, email, papeis }, segredo, {
        algorithm: ALGORITMO,
        subject: usuario,
        expiresIn: expiraEm,
        issuer: emissor,
        audience: audiencia
      });
    },
    // Algoritmo fixado na verificação: bloqueia "alg: none" e troca de algoritmo
    verificar(token) {
      return jwt.verify(token, segredo, { algorithms: [ALGORITMO], issuer: emissor, audience: audiencia });
    }
  };
}
