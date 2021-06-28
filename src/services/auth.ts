import { Inject, Service } from 'typedi';
import crypto from 'crypto';

import { IUserInputDTO } from '../interfaces/IUser';
import { UserStatus, EmailTemplates, UserRole } from '../interfaces/types';
import EmailService from './emailService/email';

@Service()
export default class AuthService {
  constructor(
    @Inject('userModel') private userModel: Models.UserModel,
    @Inject('logger') private logger,
    private mailer: EmailService,
  ) {
  }

  public async signup(userInputDTO: IUserInputDTO): Promise<{ message: string }> {
    // validate request
    const user = await this.userModel.findOne({email: userInputDTO.email});

    // check if account exist and if is inactive
    if (user && user.status === UserStatus.INACTIVE) {
      // update expire date
      user.verificationToken.expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      user.save();

      await this.mailer.sendTemplateEmail(
        user.email,
        'Sign-up Verification API - Verify Email',
        EmailTemplates.VERIFY_EMAIL,
        {
          name: user.name,
          token: user.verificationToken.token,
        }
      );

      throw 'Register but not verified, please check your email for verification instructions';
    }
    // check if account exist and if is verified
    if (user) {
      // send already registered error in email to prevent account enumeration
      await this.mailer.sendTemplateEmail(
        user.email,
        'Sign-up Verification API - Email Already Registered',
        EmailTemplates.ALREADY_REGISTERED,
        user
      );

      throw 'You are already registered';
    }

    // check username
    const username = await this.userModel.findOne({ username: userInputDTO.username });
    if (username) throw `Username ${userInputDTO.username} is already exist in database.`;

    // check if first registered account
    const isFirstAccount = (await this.userModel.countDocuments({})) === 0;

    // create user
    this.logger.silly('Creating user db record');
    const verifyToken = AuthService.randomTokenString();
    const expireToken = new Date(Date.now() + 24 * 60 * 60 * 1000); // create verify token that expires after 24 hours
    // create user object
    const userRecord = await this.userModel.create({
      ...userInputDTO,
      verificationToken: {
        token: verifyToken,
        expires: expireToken,
      },
      role: isFirstAccount ? UserRole.ADMIN : UserRole.GUEST,
    });

    if (!userRecord) throw 'User cannot be created';

    this.logger.silly('Sending verify email');
    await this.mailer.sendTemplateEmail(
      userInputDTO.email,
      'Sign-up Verification API - Verify Email',
      EmailTemplates.VERIFY_EMAIL,
      {
        name: userInputDTO.name,
        token: verifyToken,
      },
    );

    return {message: 'Registration successful, please check your email for verification instructions'};
  }

  // helpers
  private static randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
  }
}
