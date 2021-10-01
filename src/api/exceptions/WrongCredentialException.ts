import HttpException from "./HttpException";

class WrongCredentialException extends HttpException {
  constructor() {
    super(401, 'Wrong credentials provided');
  }
}

export default WrongCredentialException;
