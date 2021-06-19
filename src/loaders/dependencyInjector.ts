import { Container } from 'typedi';

import LoggerInstance from './logger';
import config from '../config';

export default ({ mongoConnection, models}: { mongoConnection: any; models: { name: string; model: any }[] }) => {
  try {
    models.map(m => {
      Container.set(m.name, m.model);
    });

    // Logger instance
    Container.set('logger', LoggerInstance);


  } catch (err) {
    LoggerInstance.error('Error on dependency injector loader: ', err);
    throw err;
  }
}
