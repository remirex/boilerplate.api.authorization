import { NextFunction, Request, Response } from 'express';

import logger from '../../loaders/logger';

/**
 * The validate request middleware function validates the body of a request against a Joi schema object.
 * @param req
 * @param res
 * @param next
 * @param schema
 */
export default (req: Request, res: Response, next: NextFunction, schema ) => {
  const options = {
    abortEarly: false, // include all errors
    allowUnknown: true, // ignore unknown props
    stripUnknown: true, // remove unknown props
  };

  const { error, value } = schema.validate(req.body, options);

  if (error) {
    const { details } = error;
    const errorsDetail = details.map(i => i);
    logger.info(errorsDetail);
    const allErrors: any = [];
    errorsDetail.map(item => {
      allErrors.push({
        message: item.message.replace(/"/g, ''),
        field: item.context,
      });
    });
    res.status(422).json({
      name: 'Validation Error.',
      message: 'Some fields are not valid.',
      status: false,
      errors: allErrors,
    });
  } else {
    req.body = value;
    next();
  }
}
