import { Router, Request, Response, NextFunction } from 'express';
import { Container } from 'typedi';
import { Logger } from 'winston';
import Joi from 'joi';

import AuthService from '../../services/auth';
import { IUserInputDTO } from '../../interfaces/IUser';
import middleware from '../middlewares';

const route = Router();

export default (app: Router) => {
  app.use('/auth', route);

  route.post('/signup', signupSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Register endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.signup(req.body as IUserInputDTO);
      return res.status(201).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });
}

function signupSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'io'] } })
      .required(),
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().required().min(8).max(20).pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    repeatPassword: Joi.ref('password'),
    acceptTerms: Joi.boolean().required().invalid(false),
  }).with('password', 'repeatPassword');
  middleware.joiValidation(req, res, next, schema);
}
