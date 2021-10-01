import jwt from 'jsonwebtoken';
import config from '../../config';
import { NextFunction, Request, Response } from 'express';

const getTokenFromHeader = req => {
  if (
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Token') ||
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer')
  ) {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

const isAllowed = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = getTokenFromHeader(req);
    try {
      const decoded = jwt.verify(token, config.jwtSecret);
      if (!roles.includes(decoded['role'])) {
        return res.status(405).json({ message: 'Not Allowed.' });
      }

      next();
    } catch (err) {
      return res.status(err.status).json({ errors: { message: err.message } });
    }
  };
};

export default isAllowed;
