import HttpException from "./HttpException";

class WrongTokenException extends HttpException {
  constructor() {
    super(400, 'Wrong token');
  }
}

export default WrongTokenException;
