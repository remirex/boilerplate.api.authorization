import { Service, Inject } from 'typedi';

import config from '../../config';
import { EmailTemplates } from '../../interfaces/types';
import { verifyUser } from './templates/verifyUser';
import { alreadyRegistered } from './templates/alreadyRegistered';

@Service()
export default class EmailService {
  constructor(
    @Inject('emailClient') private emailClient,
    @Inject('logger') private logger,
  ) {}

  private async sendEmail(to: string, subject: string, content: string) {
    const emailData = {
      from: config.emails.from,
      to: to,
      subject: subject,
      html: content,
    };

    await this.emailClient.sendMail(emailData);

    return { delivered: 1, status: 'ok' };
  }

  public sendTemplateEmail(to: string, subject: string, template: string, data) {
    this.logger.info(`send template email to ${to}`);
    let content = '';
    switch (template) {
      case EmailTemplates.VERIFY_EMAIL:
        content = verifyUser(data);
        break;
      case EmailTemplates.ALREADY_REGISTERED:
        content = alreadyRegistered(data);
        break;
      default:
    }
    return this.sendEmail(to, subject, content);
  }
}
