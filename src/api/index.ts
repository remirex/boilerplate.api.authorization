import { Router } from 'express';
import auth from './routes/auth';
import file from './routes/file/files';

// guaranteed to get dependencies
export default () => {
  const app = Router();

  // routes
  auth(app);
  file(app);

  return app;
}
