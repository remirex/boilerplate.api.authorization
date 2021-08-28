import {Inject, Service} from 'typedi';
import { Post, Get, Route, Query, Body, Tags, Hidden, Security, Request } from 'tsoa';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

import EmailService from './emailService/email';
import {IUserInputDTO, IUserInputSignIn, IUserInputToken,ResetPasswordDto} from '../interfaces/IUser';
import {EmailTemplates, UserRole, UserStatus} from '../interfaces/types';
import config from '../config';
import {IUserInputEmail} from "../interfaces/IUser";

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

  /**
   * Register a new user account and send a verification email.
   * The first account registered in the system is assigned the `ADMIN` role, other accounts are assigned the `GUEST` role.
   * @param signUpUserDto
   */
  @Post("/signup")
  public async signup(@Body() signUpUserDto: IUserInputDTO): Promise<{ message: string }> {
    const user = await this.userModel.findOne({email: signUpUserDto.email});

    if (user && user.status === UserStatus.INACTIVE) {
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

    if (user) {
      await this.mailer.sendTemplateEmail(
        user.email,
        'Sign-up Verification API - Email Already Registered',
        EmailTemplates.ALREADY_REGISTERED,
        user
      );

      throw 'You are already registered';
    }

    const username = await this.userModel.findOne({ username: signUpUserDto.username });
    if (username) throw `Username ${signUpUserDto.username} is already exist in database.`;

    const isFirstAccount = (await this.userModel.countDocuments({})) === 0;

    this.logger.silly('Creating user db record');
    const verifyToken = AuthService.randomTokenString();
    const expireToken = new Date(Date.now() + 24 * 60 * 60 * 1000); // create verify token that expires after 24 hours

    const userRecord = await this.userModel.create({
      ...signUpUserDto,
      verificationToken: {
        token: verifyToken,
        expires: expireToken,
      },
      role: isFirstAccount ? UserRole.ADMIN : UserRole.GUEST,
    });

    if (!userRecord) throw 'User cannot be created';

    this.logger.silly('Sending verify email');
    await this.mailer.sendTemplateEmail(
      signUpUserDto.email,
      'Sign-up Verification API - Verify Email',
      EmailTemplates.VERIFY_EMAIL,
      {
        name: signUpUserDto.name,
        token: verifyToken,
      },
    );

    return {message: 'Registration successful, please check your email for verification instructions'};
  }

  /**
   * Verify a new account with a verification token received by email after registration
   * @param verifyEmailInput
   */
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

  /**
   * Authenticate account credentials and return a JWT token and refresh token.
   * Accounts must be verified before authenticating.
   * @param signInInput
   * @param ipAddress
   */
  @Post("/signin")
  public async signin(@Body() signInInput: IUserInputSignIn, @Query() @Hidden() ipAddress?: string) {
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

  /**
   * Use a refresh token to generate a new JWT token and a new refresh token
   * @param refreshTokenInput
   * @param ipAddress
   */
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

  /**
   * Revoke a refresh token.
   * Admin users can revoke the tokens of any account, regular users can only revoke their own tokens.
   * @param authHeader
   * @param revokeTokenInput
   * @param ipAddress
   */
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

  /**
   * Send a token to the email which will allow you to reset the password of the account
   * @param forgotPasswordInput
   */
  @Post("/forgot-password")
  public async forgotPassword(
    @Body() forgotPasswordInput: IUserInputEmail
  ): Promise<{ message: string }> {
    const user = await this.userModel.findOne({ email: forgotPasswordInput.email });

    // always return ok response to prevent email enumeration
    if (!user) throw 'User not found';

    user.resetToken = {
      token: AuthService.randomTokenString(),
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    await user.save();

    await this.mailer.sendTemplateEmail(
      forgotPasswordInput.email,
      'Sign-up Verification API - Reset Password',
      EmailTemplates.RESET_PASSWORD,
      {
        username: user.username,
        token: user.resetToken.token,
      }
    )

    return { message: 'Please check your email for password reset instructions' };
  }

  /**
   * Password reset token received in the email from the forgot password step
   * @param resetPasswordDto
   */
  @Post('/reset-password')
  public async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto
  ): Promise<{ message: string}> {
    const user = await this.userModel.findOne({
      'resetToken.token': resetPasswordDto.token,
      'resetToken.expires': { $gt: Date.now() },
    });

    if (!user) throw 'Invalid token';

    const hash = await this.password.toHash(resetPasswordDto.password);

    await this.userModel.updateOne(
      { 'resetToken.token': resetPasswordDto.token },
      {
        $set: {
          password: hash,
          passwordReset: Date.now(),
          resetToken: undefined
        },
      },
    );

    return { message: 'Password reset successful, you can now login' };
  }

  /**
   * Current user details
   * @param user
   */
  @Security("jwt")
  @Get('/me')
  public async currentUser(@Request() user): Promise<{}> {
    return user;
  }

  /**
   * Generate two factor authentication code
   * @param userId
   * @param response
   */
  @Security("jwt")
  @Post('/2fa/generate')
  public async generateTwoFactorAuthenticationCode(@Request() userId: string, @Request() response) {
    const secretCode = speakeasy.generateSecret({
      name: config.twoFactorAppName,
    });

    this.userModel.findByIdAndUpdate(userId, {
      twoFactorAuthenticationCode: secretCode.base32,
    });

    return QRCode.toFileStream(response, secretCode.otpauth_url!);
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
    const decoded: any = jwt.decode(authHeader);

    const account = await this.userModel.findById(decoded.id);
    const refreshTokens = await this.refreshTokenModel.find({ account: account!._id });

    const found = refreshTokens.some(item => {
      return item.token === refreshToken.token;
    });

    return !!found;
  }
}
