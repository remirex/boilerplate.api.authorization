import { Router, Request, Response, NextFunction } from 'express';
import { Container } from 'typedi';
import { Logger } from 'winston';
import Joi from 'joi';

import AuthService from '../../services/auth';
import { IUserInputDTO } from '../../interfaces/IUser';
import middleware from '../middlewares';

const route = Router();

export default (app: Router) => {

}
