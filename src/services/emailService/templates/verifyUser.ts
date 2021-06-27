import config from '../../../config';

export const verifyUser = (
  { token, name }: { token: string, name: string }
): string => `
  <html lang="en">
    <head>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>${token} is your verification token</title>
    <div style="padding: 10px ; line-height: 18px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 12px; color:#1C1C1C; max-width: 800px; margin: 0 auto; text-align: left;">
      <div style="display:block; padding: 20px; width: 100%; background-color: #000">
      <h1 style="color: #FFA500">F Team App</h1>
      </div>
      <div style="display:block; box-sizing: border-box; width: 100%; padding: 40px 50px; line-height: 30px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 16px; color:#1C1C1C; background-color: #ffffff; border-bottom: 6px solid #FFA500; border-top: 6px solid #FFA500;">
        <h3>Hi, ${name}</h3>
        <p>Please click on the following link, or paste this into your browser to complete the process:</p>
        <p><b>${config.clientUrl}/verify?token=${token}</b></p>
        <p>If you didn't request this link, you can ignore<br>this message.</p>
        <p>If you have any questions please reply to this email or contact us at <a href="mailto:mirkoj@software-nation.com">mirkoj@software-nation.com</a></p>
        <p>Thanks,<br />F Team</p>
      </div>
      <div style="display: block; text-align: center; padding: 5px; width: 100%; background-color: #000">
      <h2 style="color: #FFA500">Powered by FTeam</h2>
      <h3 style="color: #FFA500">&copy; 2021 mirkoj@software-nation.com</h3>
      </div>
    </div>
    </body>
    </html>
`;
