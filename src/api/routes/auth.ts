import {NextFunction, Request, Response, Router} from 'express';
import {Container} from 'typedi';
import {Logger} from 'winston';
import Joi from 'joi';

import AuthService from '../../services/auth';
import {IUserInputDTO} from '../../interfaces/IUser';
import {UserRole} from '../../interfaces/types';
import middleware from '../middlewares';

const route = Router();

export default (app: Router) => {
  app.use('/auth', route);

  route.post('/signup', signUpSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling SignUp endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.signup(req.body as IUserInputDTO);
      return res.status(201).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/verify', verifySchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Verify Email endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.verifyEmail(req.body.token);
      return res.status(200).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/signin', signInSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling SignIn endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.signin(req.body.email, req.body.password, req.ip);
      return res.status(200).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/refresh-token', refreshTokenSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Refresh Token endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.refreshToken(req.body.token, req.ip);
      return res.status(200).json(response);
    }catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/revoke-token',
    revokeTokenSchema,
    middleware.auth,
    middleware.allow([UserRole.ADMIN, UserRole.GUEST]),
    async (req: Request, res: Response, next: NextFunction) => {
      const logger: Logger = Container.get('logger');
      logger.debug('Calling Revoke Token endpoint with body: %o', req.body);
      try {
        let authHeader;
        if (
          (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Token') ||
          (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer')
        ) {
          authHeader = req.headers.authorization.split(' ')[1];
        }
        const authServiceInstance = Container.get(AuthService);
        const response = await authServiceInstance.revokeToken(authHeader, req.body.token, req.ip);
        return res.status(200).json(response);
      } catch (error) {
        logger.error('🔥 error: %o', error);
        return next(error);
      }
    });
}

function signUpSchema(req: Request, res: Response, next: NextFunction) {
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

function verifySchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}

function signInSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'io'] } })
      .required(),
    password: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}

function refreshTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}

function revokeTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}
