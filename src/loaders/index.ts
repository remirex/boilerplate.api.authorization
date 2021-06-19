import expressLoader from './express';
import mongooseLoader from './mongoose';
import dependencyInjectorLoader from './dependencyInjector';
import Logger from './logger';


export default async ({expressApp}: any) => {
  const mongoConnection = await mongooseLoader();
  Logger.info('DB loaded and connected!');

  const userModel = {
    name: 'userModel',
    // Notice the require syntax and the '.default'
    model: require('../models/user').default,
  };

  await dependencyInjectorLoader({
    mongoConnection,
    models: [userModel],
  });
  Logger.info('Dependency Injector loaded');

  await expressLoader({app: expressApp});
  Logger.info('Express loaded!');
}
