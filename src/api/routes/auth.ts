import {NextFunction, Request, Response, Router} from 'express';
import {Container} from 'typedi';
import {Logger} from 'winston';

import AuthService from '../../services/auth';
import {IUserInputDTO,IUserInputSignIn,IUserInputToken} from '../../interfaces/IUser';
import {UserRole} from '../../interfaces/types';
import middleware from '../middlewares';
import request from "../requests";
import {IUserInputEmail} from "../../interfaces/IUser";

const route = Router();

export default (app: Router) => {
  app.use('/auth', route);

  route.post('/signup', request.signUpSchema, async (req: Request, res: Response, next: NextFunction) => {
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

  route.post('/verify', request.verifySchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Verify Email endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.verifyEmail(req.body as IUserInputToken);
      return res.status(200).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/signin', request.signInSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling SignIn endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.signin(req.body as IUserInputSignIn, req.ip);
      return res.status(200).json(response);
    } catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/refresh-token', request.refreshTokenSchema, async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Refresh Token endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const response = await authServiceInstance.refreshToken(req.body as IUserInputToken, req.ip);
      return res.status(200).json(response);
    }catch (error) {
      logger.error('🔥 error: %o', error);
      return next(error);
    }
  });

  route.post('/revoke-token',
    request.revokeTokenSchema,
    middleware.expressAuthentication('jwt'),
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
        const response = await authServiceInstance.revokeToken(authHeader, req.body as IUserInputToken, req.ip);
        return res.status(200).json(response);
      } catch (error) {
        logger.error('🔥 error: %o', error);
        return next(error);
      }
    });

  route.post('/forgot-password',
    request.forgotPasswordSchema,
    async (req: Request, res: Response, next: NextFunction) => {
      const logger: Logger = Container.get('logger');
      logger.debug('Calling Forgot Password endpoint with body: %o', req.body);
      try {
        const authServiceInstance = Container.get(AuthService);
        const response = await authServiceInstance.forgotPassword(req.body as IUserInputEmail);
        return res.status(200).json(response);
      } catch (error) {
        logger.error('🔥 error: %o', error);
        return next(error);
      }
    });

  route.post('reset-password',
    request.resetPasswordSchema,
    async (req: Request, res: Response, next: NextFunction) => {
      const logger: Logger = Container.get('logger');
      logger.debug('Calling Reset Password endpoint with body: %o', req.body);
      try {

      } catch (error) {
        logger.error('🔥 error: %o', error);
        return next(error);
      }
    });
}
