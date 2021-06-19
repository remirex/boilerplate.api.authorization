import {Inject, Service} from 'typedi';

import { IUserInputDTO } from '../interfaces/IUser';

@Service()
export default class AuthService {
  constructor(
    @Inject('userModel') private userModel: Models.UserModel,
    @Inject('logger') private logger,
  ) {}

  public async register(): Promise<{ message: any }> {
    // validate request

    // check if account exist and if is inactive

    // check if account exist and if is verified

    // check username

    // check if first registered account is admin

    // create user

    return { message: 'Registration successful, please check your email for verification instructions' }
  }
}
