import HttpException from "./HttpException";

class CannotCreateRecordException extends HttpException {
  constructor() {
    super(400, 'Record cannot be created');
  }
}

export default CannotCreateRecordException;
