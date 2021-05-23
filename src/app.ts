// TODO: 'import reflect metadata'
import express from 'express';

import config from '../src/config';
import Logger from '../src/loaders/logger';

const app = express();

/**
 * A little hack here
 * Import/Export can only be used in 'top-level code'
 * Well, at least in node 10 without babel and at the time of writing
 * So we are using good old require.
 **/
require('./loaders').default({expressApp: app});

const server = app.listen(config.port, function () {
  Logger.info(`Webserver is ready and listening on port ${config.port}`);
}).on('error', err => {
  Logger.error(err);
  process.exit(1);
});

// quit on ctrl-c when running docker in terminal
process.on('SIGINT', function onSigint() {
  Logger.info('Got SIGINT (aka ctrl-c in docker). Graceful shutdown ', new Date().toISOString());
  shutdown();
});

// quit properly on docker stop
process.on('SIGTERM', function onSigterm() {
  Logger.info('Got SIGTERM (docker container stop). Graceful shutdown ', new Date().toISOString());
  shutdown();
});

// shut down server
function shutdown() {
  server.close(function onServerClosed(err: any) {
    if (err) {
      Logger.error(err);
      process.exitCode = 1;
    }
    process.exit();
  });
}

