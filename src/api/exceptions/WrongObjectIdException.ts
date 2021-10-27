import HttpException from "./HttpException";

class WrongObjectIdException extends HttpException {
  constructor() {
    super(400, 'Wrong object id');
  }
}

export default WrongObjectIdException;
