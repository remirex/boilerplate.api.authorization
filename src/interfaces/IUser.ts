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
  verified: number;
  role: string;
}

export interface IUserInputDTO {
  email: string;
  name: string;
  username: string;
  password: string;
  acceptTerms: boolean;
}
