import { Request, Response, NextFunction } from 'express';

export const errorHandler = (err, req: Request, res: Response, next: NextFunction) => {
  switch (true) {
    case typeof err === 'string':
      // custom application error
      const is404 = err.toLowerCase().endsWith('not found');
      const statusCode = is404 ? 404 : 400;
      return res.status(statusCode).json({ message: err });
    case err.name === 'ValidationError':
      // mongoose validation error
      return res.status(400).json({ message: err.message });
    case err.name === 'UnauthorizedError':
      // jwt authentication error
      return res.status(err.status).json({ message: err.message }).end();
    default:
      return res.status(500).json({ message: err.message });
  }
};
