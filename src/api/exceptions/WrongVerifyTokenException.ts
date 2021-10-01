import HttpException from "./HttpException";

class WrongVerifyTokenException extends HttpException {
  constructor() {
    super(400, 'Wrong verify account token');
  }
}

export default WrongVerifyTokenException;
