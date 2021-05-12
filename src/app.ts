// TODO: 'import reflect metadata'
// TODO: 'import config file'
import express from 'express';
// TODO: 'import Logger'

async function startServer() {
  const app = express();

  /**
   * A little hack here
   * Import/Export can only be used in 'top-level code'
   * Well, at least in node 10 without babel and at the time of writing
   * So we are using good old require.
   **/
  await require('./loaders').default({ expressApp: app });

  app.listen(3000, () => {
    // TODO: 'add logger !!!'
    console.log('Server listening on port: 3000')
  }).on('error', err => {
    process.exit(1);
  });
}

startServer().then();
