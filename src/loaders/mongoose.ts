import mongoose from 'mongoose';
import {Db} from 'mongodb';

import config from '../config';

// local development
let url = `mongodb://${config.mongoHostname}:${config.mongoPort}/${config.mongoDatabase}`;

if (process.env.NODE_ENV == 'production') url = `mongodb://${config.mongoUsername}:${config.mongoPassword}@${config.mongoHostname}/${config.mongoDatabase}?retryWrites=true&w=majority`;


export default async (): Promise<Db> => {
  const connection = await mongoose.connect(url, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
  });

  return connection.connection.db;
}
