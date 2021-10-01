import HttpException from "./HttpException";

class WrongTwoFactorAuthenticationCodeException extends HttpException {
  constructor() {
    super(400, 'Wrong two factor authentication code');
  }
}

export default WrongTwoFactorAuthenticationCodeException;
