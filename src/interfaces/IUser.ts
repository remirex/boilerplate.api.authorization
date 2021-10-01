export interface IUser {
  id: string;
  email: string;
  name: string;
  password: string;
  username: string;
  status: string;
  verificationToken: {
    token: string,
    expires: Date
  };
  resetToken: {
    token: string,
    expires: Date
  }
  verified: number;
  role: string;
  twoFactorAuthenticationCode: string;
  isTwoFactorAuthenticationEnabled: boolean;
}

export interface IRefreshToken {
  id: string;
  user: object;
  token: string;
  createdByIp: string;
  revokedByIp: string;
  isActive: boolean;
  revoked: number;
  replacedByToken: string;
}

export interface CreateUserDto {
  email: string;
  name: string;
  username: string;
  password: string;
  repeatPassword: string;
  acceptTerms: boolean;
}
export interface LogInDto {
  email: string;
  password: string;
}

export interface TokenDto {
  token: string;
}

export interface ForgotPasswordDto {
  email: string;
}

export interface ResetPasswordDto {
  token: string;
  password: string;
  repeatPassword: string;
}

export interface TwoFactorAuthenticationDto {
  code: string;
}

export interface DataStoredInTokenDto {
  id: string;
  role: string;
  isSecondFactorAuthenticated: boolean;
}
