import config from '../../../config';

export const passwordResetEmail = ({ username, token }: { token: string; username: string }): string =>
  `<html lang="en">
    <head>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>Password Reset Email</title>
    <div style="padding: 10px ; line-height: 18px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 12px; color:#1C1C1C; max-width: 800px; margin: 0 auto; text-align: left;">
      <div style="display:block; padding: 20px; background-color: #55237d">
      <h1 style="color: #fff">F Team App</h1>
      </div>
      <div style="display:block; box-sizing: border-box; padding: 40px 50px; line-height: 30px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 16px; color:#1C1C1C; background-color: #ffffff;">
        <h1>Change your password</h1>
        <p>You are receiving this because you (or someone else) requested the reset of the ${username} f team app user account.</p>
        <p>Please click on the following link, or paste this into your browser to complete the process:</p>
        <p><b><a href="${config.clientUrl}/password/reset?token=${token}" style="color: #55237d">reset password link</a> </b></p>
        <p>Reset link expire after 24 hours.</p>
        <p>If you didn't request this change, ignore this
        <br>message and your password will remain the<br>
        same.</p>
        <p>If you have any questions please reply to this email or contact us at <a href="mailto:mirkoj@software-nation.com" style="color: #55237d">mirkoj@software-nation.com</a></p>
        <p>Thanks,<br />F Team</p>
      </div>
      <div style="display: block; text-align: center; padding: 5px; background-color: #55237d">
      <h2 style="color: #fff">Powered by FTeam</h2>
      <h3 style="color: #fff">&copy; 2021 mirkoj@software-nation.com</h3>
    </div>
    </body>
    </html>`; // html body
