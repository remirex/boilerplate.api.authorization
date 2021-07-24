import {Inject, Service} from 'typedi';
import { Post, Route, Query, Body, Tags, Hidden, Security } from 'tsoa';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import EmailService from './emailService/email';
import {IUserInputDTO, IUserInputSignIn, IUserInputToken} from '../interfaces/IUser';
import {EmailTemplates, UserRole, UserStatus} from '../interfaces/types';
import config from '../config';

@Tags("User")
@Route("/auth")
@Service()
export default class AuthService {
  constructor(
    @Inject('userModel') private userModel: Models.UserModel,
    @Inject('refreshTokenModel') private refreshTokenModel: Models.RefreshTokenModel,
    @Inject('logger') private logger,
    @Inject('password') private password,
    private mailer: EmailService,
  ) {}

  @Post("/signup")
  public async signup(@Body() userInputDTO: IUserInputDTO): Promise<{ message: string }> {
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

  @Post("/verify")
  public async verifyEmail(@Body() verifyEmailInput: IUserInputToken): Promise<{ message: string }> {

    const user = await this.userModel.findOne({
      'verificationToken.token': verifyEmailInput.token,
      'verificationToken.expires': { $gt: Date.now() },
    });

    if (!user) throw 'Invalid token';

    user.verified = Date.now();
    user.status = UserStatus.ACTIVE;
    user.verificationToken = {} as any;
    user.save();

    return { message: 'Verification successful, you can now login' };
  }

  @Post("/signin")
  public async signin(@Body() signInInput: IUserInputSignIn, @Query() @Hidden() ipAddress?: string) {
    // email: string, password: string, ipAddress: string
    const user = await this.userModel.findOne({ email: signInInput.email });

    if (!user) throw 'User not registered.';

    if (user.status !== UserStatus.ACTIVE) throw 'User not verified yet';

    this.logger.silly('Checking password');
    const validPassword = await this.password.compare(user.password, signInInput.password);
    if (!validPassword) throw 'Invalid password';
    this.logger.silly('Password is valid!');

    this.logger.silly('Generating JWT');
    const jwtToken = await AuthService.generateJwtToken(user);
    const refreshToken = await this.generateRefreshToken(user, ipAddress!);

    return {
      auth: true,
      jwtToken,
      refreshToken: refreshToken.token,
    };
  }

  @Post("/refresh-token")
  public async refreshToken(@Body() refreshTokenInput: IUserInputToken, @Query() @Hidden() ipAddress?: string) {
    const oldRefreshToken = await this.getRefreshToken(refreshTokenInput.token);

    const account: any = oldRefreshToken;

    const newRefreshToken = await this.generateRefreshToken(oldRefreshToken, ipAddress!);

    oldRefreshToken.revoked = Date.now();
    oldRefreshToken.revokedByIp = ipAddress!;
    oldRefreshToken.replacedByToken = newRefreshToken.token;

    await oldRefreshToken.save();

    const jwt = await AuthService.generateJwtToken(account);

    return {
      auth: true,
      jwt,
      refreshToken: newRefreshToken.token,
    }
  }

  @Security("jwt")
  @Post("/revoke-token")
  public async revokeToken(
    @Query() @Hidden() authHeader = null,
    @Body() revokeTokenInput: IUserInputToken,
    @Query() @Hidden() ipAddress?: string
  ): Promise<{ message: string }> {
    const findToken = await this.getRefreshToken(revokeTokenInput.token);

    const isOwner = await this.tokenOwner(findToken, authHeader!);
    if (!isOwner) throw 'User is not owner for this token';

    findToken.revoked = Date.now();
    findToken.revokedByIp = ipAddress!;
    await findToken.save();

    return { message: 'Token revoked' };
  }

  // helpers
  private static randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
  }

  private static async generateJwtToken(account: { id: string; role: string }) {
    // create a jwt token containing the user id that expires in 15 minutes
    return jwt.sign({ sub: account.id, id: account.id, role: account.role }, config.jwtSecret, {
      expiresIn: '15m',
    });
  }

  private async generateRefreshToken(account: { id: string }, ipAddress: string) {
    // create a refresh token that expires in 7 days
    return await this.refreshTokenModel.create({
      account: account.id,
      token: AuthService.randomTokenString(),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdByIp: ipAddress,
    });
  }

  private async getRefreshToken(token: string) {
    const refreshToken = await this.refreshTokenModel.findOne({ token }).populate('User');
    if (!refreshToken || !refreshToken.isActive) throw 'invalid token';

    return refreshToken;
  }

  private async tokenOwner(refreshToken: { token: string }, authHeader: string) {
    // decode token
    const decoded: any = jwt.decode(authHeader);
    console.log('decoded token:', decoded);

    // find tokens & account
    const account = await this.userModel.findById(decoded.id);
    const refreshTokens = await this.refreshTokenModel.find({ account: account!._id });

    // check if tokens match
    const found = refreshTokens.some(item => {
      return item.token === refreshToken.token;
    });

    return !!found;
  }
}
