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
}

export interface IRefreshToken {
  id: string;
  token: string;
  createdByIp: string;
  revokedByIp: string;
  isActive: boolean;
  revoked: number;
  replacedByToken: string;
}

export interface IUserInputDTO {
  email: string;
  name: string;
  username: string;
  password: string;
  repeatPassword: string;
  acceptTerms: boolean;
}

export interface IUserInputSignIn {
  email: string;
  password: string;
}

export interface IUserInputToken {
  token: string;
}

export interface IUserInputEmail {
  email: string;
}

export interface ResetPasswordDto {
  token: string;
  password: string;
}
