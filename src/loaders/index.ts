import expressLoader from './express';
import mongooseLoader from './mongoose';
import dependencyInjectorLoader from './dependencyInjector';
import Logger from './logger';


export default async ({expressApp}: any) => {
  const mongoConnection = await mongooseLoader();
  Logger.info('DB loaded and connected!');

  // app models
  const userModel = {
    name: 'userModel',
    // Notice the require syntax and the '.default'
    model: require('../models/user').default,
  };

  const refreshTokenModel = {
    name: 'refreshTokenModel',
    // Notice the require syntax and the '.default'
    model: require('../models/refreshToken').default,
  };

  await dependencyInjectorLoader({
    mongoConnection,
    models: [userModel, refreshTokenModel],
  });
  Logger.info('Dependency Injector loaded');

  await expressLoader({app: expressApp});
  Logger.info('Express loaded!');
}
