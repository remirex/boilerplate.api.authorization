import {Inject, Service} from 'typedi';
import {Body, Get, Hidden, Post, Query, Request, Route, Security, Tags} from 'tsoa';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

import EmailService from './emailService/email';
import {
  CreateUserDto,
  DataStoredInTokenDto,
  ForgotPasswordDto,
  LogInDto,
  ResetPasswordDto,
  TokenDto,
  TwoFactorAuthenticationDto,
} from '../interfaces/IUser';
import UserWithThatEmailAlreadyExistsException from "../api/exceptions/UserWithThatEmailAlreadyExistsException";
import UserWithThatEmailAlreadyRegisterButNotVerifiedException
  from "../api/exceptions/UserWithThatEmailAlreadyRegisterButNotVerifiedException";
import UserWithThatUsernameAlreadyExistsException from "../api/exceptions/UserWithThatUsernameAlreadyExistsException";
import CannotCreateRecordException from "../api/exceptions/CannotCreateRecordException";
import WrongVerifyTokenException from "../api/exceptions/WrongVerifyTokenException";
import NotVerifiedException from "../api/exceptions/NotVerifiedException";
import UserNotFoundException from "../api/exceptions/UserNotFoundException";
import WrongTokenException from "../api/exceptions/WrongTokenException";
import NotAllowedException from "../api/exceptions/NotAllowedException";
import WrongTwoFactorAuthenticationCodeException from "../api/exceptions/WrongTwoFactorAuthenticationCodeException";
import WrongCredentialException from "../api/exceptions/WrongCredentialException";
import {IUser} from "../interfaces/IUser";
import {EmailTemplates, UserRole, UserStatus} from '../interfaces/types';
import config from '../config';
import logger from "../loaders/logger";
import User from "../models/user";

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
  ) {
  }

  /**
   * Register a new user account and send a verification email.
   * The first account registered in the system is assigned the `ADMIN` role, other accounts are assigned the `GUEST` role.
   * @param userData
   */
  @Post("/signup")
  public async signup(@Body() userData: CreateUserDto): Promise<{ message: string }> {
    const user = await this.userModel.findOne({email: userData.email});

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

      throw new UserWithThatEmailAlreadyRegisterButNotVerifiedException();
    }

    if (user) {
      await this.mailer.sendTemplateEmail(
        user.email,
        'Sign-up Verification API - Email Already Registered',
        EmailTemplates.ALREADY_REGISTERED,
        user
      );

      throw new UserWithThatEmailAlreadyExistsException(userData.email);
    }

    const username = await this.userModel.findOne({username: userData.username});
    if (username) throw new UserWithThatUsernameAlreadyExistsException(userData.username);

    const isFirstAccount = (await this.userModel.countDocuments({})) === 0;

    this.logger.silly('Creating user db record');
    const verifyToken = AuthService.randomTokenString();
    const expireToken = new Date(Date.now() + 24 * 60 * 60 * 1000); // create verify token that expires after 24 hours

    const userRecord = await this.userModel.create({
      ...userData,
      verificationToken: isFirstAccount ? {} : {token: verifyToken, expires: expireToken},
      role: isFirstAccount ? UserRole.ADMIN : UserRole.GUEST,
      status: isFirstAccount ? UserStatus.ACTIVE : UserStatus.INACTIVE,
      verified: isFirstAccount ? Date.now() : null,
    });

    if (!userRecord) throw new CannotCreateRecordException();

    this.logger.silly('Sending verify email');
    await this.mailer.sendTemplateEmail(
      userData.email,
      'Sign-up Verification API - Verify Email',
      EmailTemplates.VERIFY_EMAIL,
      {
        name: userData.name,
        token: verifyToken,
      },
    );

    return {message: 'Registration successful, please check your email for verification instructions'};
  }

  /**
   * Verify a new account with a verification token received by email after registration
   * @param verifyEmailData
   */
  @Post("/verify")
  public async verifyEmail(@Body() verifyEmailData: TokenDto): Promise<{ message: string }> {

    const user = await this.userModel.findOne({
      'verificationToken.token': verifyEmailData.token,
      'verificationToken.expires': {$gt: Date.now()},
    });

    if (!user) throw new WrongVerifyTokenException();

    user.verified = Date.now();
    user.status = UserStatus.ACTIVE;
    user.verificationToken = {} as any;
    user.save();

    return {message: 'Verification successful, you can now login'};
  }

  /**
   * Authenticate account credentials and return a JWT token and refresh token.
   * Accounts must be verified before authenticating.
   * @param logInData
   * @param ipAddress
   */
  @Post("/signin")
  public async signin(@Body() logInData: LogInDto, @Query() @Hidden() ipAddress?: string) {
    const user = await this.userModel.findOne({email: logInData.email});

    if (user) {
      if (user.status === UserStatus.ACTIVE) {
        this.logger.silly('Checking password');
        const validPassword = await this.password.compare(user.password, logInData.password);
        if (validPassword) {
          this.logger.silly('Password is valid!');
          this.logger.silly('Generating JWT');
          const jwtToken = await AuthService.generateJwtToken(user);
          const refreshToken = await this.generateRefreshToken(user, ipAddress!);
          if (user.isTwoFactorAuthenticationEnabled) {
            return {
              auth: true,
              isTwoFactorAuthenticationEnabled: true,
              jwtToken,
              refreshToken: refreshToken.token,
            };
          } else {
            return {
              auth: true,
              jwtToken,
              refreshToken: refreshToken.token,
            };
          }
        } else {
          throw new WrongCredentialException();
        }
      } else {
        throw new NotVerifiedException()
      }
    } else {
      throw new WrongCredentialException();
    }
  }

  /**
   * Use a refresh token to generate a new JWT token and a new refresh token
   * @param refrashTokenData
   * @param ipAddress
   */
  @Post("/refresh-token")
  public async refreshToken(@Body() refrashTokenData: TokenDto, @Query() @Hidden() ipAddress?: string) {
    const oldRefreshToken = await this.getRefreshToken(refrashTokenData.token);

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
   * @param revokeTokenData
   * @param ipAddress
   */
  @Security("jwt")
  @Post("/revoke-token")
  public async revokeToken(
    @Query() @Hidden() authHeader = null,
    @Body() revokeTokenData: TokenDto,
    @Query() @Hidden() ipAddress?: string
  ): Promise<{ message: string }> {
    const findToken = await this.getRefreshToken(revokeTokenData.token);

    const isOwner = await this.tokenOwner(findToken, authHeader!);
    if (!isOwner) throw new NotAllowedException();

    findToken.revoked = Date.now();
    findToken.revokedByIp = ipAddress!;
    await findToken.save();

    return {message: 'Token revoked'};
  }

  /**
   * Send a token to the email which will allow you to reset the password of the account
   * @param forgotPasswordData
   */
  @Post("/forgot-password")
  public async forgotPassword(
    @Body() forgotPasswordData: ForgotPasswordDto
  ): Promise<{ message: string }> {
    const user = await this.userModel.findOne({email: forgotPasswordData.email});

    // always return ok response to prevent email enumeration
    if (!user) throw new UserNotFoundException();

    user.resetToken = {
      token: AuthService.randomTokenString(),
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    await user.save();

    await this.mailer.sendTemplateEmail(
      forgotPasswordData.email,
      'Sign-up Verification API - Reset Password',
      EmailTemplates.RESET_PASSWORD,
      {
        username: user.username,
        token: user.resetToken.token,
      }
    )

    return {message: 'Please check your email for password reset instructions'};
  }

  /**
   * Password reset token received in the email from the forgot password step
   * @param resetPasswordData
   */
  @Post('/reset-password')
  public async resetPassword(
    @Body() resetPasswordData: ResetPasswordDto
  ): Promise<{ message: string }> {
    const user = await this.userModel.findOne({
      'resetToken.token': resetPasswordData.token,
      'resetToken.expires': {$gt: Date.now()},
    });

    if (!user) throw new WrongTokenException();

    const hash = await this.password.toHash(resetPasswordData.password);

    await this.userModel.updateOne(
      {'resetToken.token': resetPasswordData.token},
      {
        $set: {
          password: hash,
          passwordReset: Date.now(),
          resetToken: undefined
        },
      },
    );

    return {message: 'Password reset successful, you can now login'};
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

    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorAuthenticationCode: secretCode.base32,
    });

    return QRCode.toFileStream(response, secretCode.otpauth_url!);
  }

  /**
   * We can create an endpoint that turns on the Two-Factor Authentication.
   * @param codeData
   * @param user
   */
  @Security("jwt")
  @Post('/2fa/turn-on')
  public async turnOnTwoFactorAuthentication(@Body() codeData: TwoFactorAuthenticationDto, @Request() user: IUser): Promise<{ message: string }> {
    const isCodeValid = await AuthService.verifyTwoFactorAuthenticationCode(codeData.code, user);

    if (isCodeValid) {
      await this.userModel.findByIdAndUpdate({_id: user.id}, {
        isTwoFactorAuthenticationEnabled: true,
      });
      return {message: 'Successfully turn on two factor auth'};
    }
    return new WrongTwoFactorAuthenticationCodeException();
  }

  /**
   * The user sends a valid code to the endpoint and is given a new JWT and Refresh token with full access
   * @param codeData
   * @param user
   * @param ipAddress
   */
  @Security("jwt")
  @Post('/2fa/authenticate')
  public async secondFactorAuthentication(@Body() codeData: TwoFactorAuthenticationDto, @Request() user: IUser, @Query() @Hidden() ipAddress?: string) {
    const isCodeValid = await AuthService.verifyTwoFactorAuthenticationCode(codeData.code, user);

    if (isCodeValid) {
      const jwtToken = await AuthService.generateJwtToken(user, true);
      const refreshToken = await this.generateRefreshToken(user, ipAddress!);
      return {
        auth: true,
        jwtToken,
        refreshToken: refreshToken.token,
      };
    }
    return new WrongTwoFactorAuthenticationCodeException();
  }

  // helpers
  private static randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
  }

  private static async generateJwtToken(account: { id: string; role: string }, isSecondFactorAuthenticated = false) {
    const dataStoredInToken: DataStoredInTokenDto = {
      id: account.id,
      role: account.role,
      isSecondFactorAuthenticated,
    };
    // create a jwt token containing the user id that expires in 1 hour
    return jwt.sign(
      dataStoredInToken,
      config.jwtSecret,
      {
        expiresIn: '1h',
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
    const refreshToken = await this.refreshTokenModel.findOne({token}).populate('User');
    if (!refreshToken || !refreshToken.isActive) throw new WrongTokenException();

    return refreshToken;
  }

  private async tokenOwner(refreshToken: { token: string }, authHeader: string) {
    const decoded: any = jwt.decode(authHeader);

    const account = await this.userModel.findById(decoded.id);
    const refreshTokens = await this.refreshTokenModel.find({account: account!._id});

    const found = refreshTokens.some(item => {
      return item.token === refreshToken.token;
    });

    return !!found;
  }

  private static async verifyTwoFactorAuthenticationCode(code: string, user: IUser) {
    return speakeasy.totp.verify({
      secret: user.twoFactorAuthenticationCode,
      encoding: 'base32',
      token: code,
    });
  }
}
