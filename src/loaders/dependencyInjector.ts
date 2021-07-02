import { Container } from 'typedi';
import nodemailer from 'nodemailer';

import LoggerInstance from './logger';
import Password from "../services/password";
import config from '../config';

export default ({ mongoConnection, models}: { mongoConnection: any; models: { name: string; model: any }[] }) => {
  try {
    models.map(m => {
      Container.set(m.name, m.model);
    });

    // Logger instance
    Container.set('logger', LoggerInstance);

    // Nodemailer instance
    Container.set(
      'emailClient',
      nodemailer.createTransport({
        host: config.emails.host,
        port: config.emails.port,
        secure: false, // true for 465, false for other ports
        auth: {
          user: config.emails.user,
          pass: config.emails.pass,
        },
      }),
    );

    // Password instance
    Container.set('password', Password);


  } catch (err) {
    LoggerInstance.error('Error on dependency injector loader: ', err);
    throw err;
  }
}
