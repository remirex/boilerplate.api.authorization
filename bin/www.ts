#!/usr/bin/env node

require('../src/app');

const chalk = require('chalk');
const clear = require('clear');
const figlet = require('figlet');

clear();
console.log(
  chalk.red(
    figlet.textSync('node-auth', { horizontalLayout: 'full' })
  )
);
