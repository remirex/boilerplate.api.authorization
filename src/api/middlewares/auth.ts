import {NextFunction, RequestHandler, Response, Request} from 'express';
import jwt from 'jsonwebtoken';

import AuthenticationTokenMissingException from "../exceptions/AuthenticationTokenMissingException";
import WrongAuthenticationTokenException from "../exceptions/WrongAuthenticationTokenException";
import config from '../../config';
import userModel from '../../models/user';
import {DataStoredInTokenDto} from "../../interfaces/IUser";

function authMiddleware(omitSecondFactor = false): RequestHandler {
  return async (request: Request, response: Response, next: NextFunction) => {
    if (
      (request.headers.authorization && request.headers.authorization.split(' ')[0] === 'Token') ||
      (request.headers.authorization && request.headers.authorization.split(' ')[0] === 'Bearer')
    ) {
      const token = request.headers.authorization.split(' ')[1];
      const secret = config.jwtSecret;

      const verificationResponse = jwt.verify(token, secret) as DataStoredInTokenDto;
      const {id, isSecondFactorAuthenticated} = verificationResponse;
      const user = await userModel.findById(id);
      if (user) {
        if (!omitSecondFactor && user.isTwoFactorAuthenticationEnabled && !isSecondFactorAuthenticated) {
          next(new WrongAuthenticationTokenException());
        } else {
          request.currentUser = user;
          next();
        }
      } else {
        next(new WrongAuthenticationTokenException());
      }
    } else {
      next(new AuthenticationTokenMissingException());
    }
  }
}

export default authMiddleware;
