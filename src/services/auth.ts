import { Inject, Service } from 'typedi';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import EmailService from './emailService/email';
import { IUserInputDTO } from '../interfaces/IUser';
import { UserStatus, EmailTemplates, UserRole } from '../interfaces/types';
import config from '../config';

@Service()
export default class AuthService {
  constructor(
    @Inject('userModel') private userModel: Models.UserModel,
    @Inject('refreshTokenModel') private refreshTokenModel: Models.RefreshTokenModel,
    @Inject('logger') private logger,
    @Inject('password') private password,
    private mailer: EmailService,
  ) {}

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

  public async verifyEmail(token: string): Promise<{ message: string }> {

    const user = await this.userModel.findOne({
      'verificationToken.token': token,
      'verificationToken.expires': { $gt: Date.now() },
    });

    if (!user) throw 'Invalid token';

    user.verified = Date.now();
    user.status = UserStatus.ACTIVE;
    user.verificationToken = {} as any;
    user.save();

    return { message: 'Verification successful, you can now login' };
  }

  public async signin(email: string, password: string, ipAddress: string) {
    const user = await this.userModel.findOne({ email: email });

    if (!user) throw 'User not registered.';

    if (user.status !== UserStatus.ACTIVE) throw 'User not verified yet';

    this.logger.silly('Checking password');
    const validPassword = await this.password.compare(user.password, password);
    if (!validPassword) throw 'Invalid password';
    this.logger.silly('Password is valid!');

    this.logger.silly('Generating JWT');
    const jwtToken = await AuthService.generateJwtToken(user);
    const refreshToken = await this.generateRefreshToken(user, ipAddress);

    return {
      auth: true,
      jwtToken,
      refreshToken: refreshToken.token,
    };
  }

  // helpers
  private static randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
  }

  private static async generateJwtToken(user: { id: string; role: string }) {
    // create a jwt token containing the user id that expires in 15 minutes
    return jwt.sign({ sub: user.id, id: user.id, role: user.role }, config.jwtSecret, {
      expiresIn: '15m',
    });
  }

  private async generateRefreshToken(user: { id: string }, ipAddress: string) {
    // create a refresh token that expires in 7 days
    return await this.refreshTokenModel.create({
      user: user.id,
      token: AuthService.randomTokenString(),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdByIp: ipAddress,
    });
  }
}
