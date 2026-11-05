import { criarApp } from './app.js';
import { carregarConfig, validarConfig } from './config.js';

// Carrega o .env, se existir (Node >= 20.12); variáveis já definidas no ambiente prevalecem
try {
  process.loadEnvFile();
} catch {
  // sem .env: segue apenas com as variáveis de ambiente
}

let config;
try {
  config = validarConfig(carregarConfig());
} catch (err) {
  console.error(`Configuração inválida: ${err.message}`);
  process.exit(1);
}

const servidor = criarApp(config).listen(config.porta, () => {
  console.log(`API de login ouvindo em http://localhost:${config.porta} (LDAP: ${config.ldap.url})`);
});

// Encerramento gracioso (Ctrl+C / docker stop)
for (const sinal of ['SIGINT', 'SIGTERM']) {
  process.once(sinal, () => servidor.close(() => process.exit(0)));
}
