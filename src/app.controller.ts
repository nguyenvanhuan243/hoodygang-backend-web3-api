import {
  Body,
  Controller,
  Get,
  Logger,
  Post,
  Res,
  Session,
} from '@nestjs/common';
import { Response } from 'express';
import { generateNonce, SiweMessage } from 'siwe';
import { AppService } from './app.service';

@Controller()
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('/auth/myInfo')
  async myInfo(@Res() res: Response, @Session() session: Record<string, any>) {
    res.send({ address: session.siwe?.data.address });
  }

  @Get('/auth/getNonce')
  async getNonce(
    @Res() res: Response,
    @Session() session: Record<string, any>,
  ) {
    session.nonce = generateNonce();
    res.send(session.nonce);
  }

  @Post('/auth/verify')
  async verify(
    @Res() res: Response,
    @Body() body: Record<string, any>,
    @Session() session: Record<string, any>,
  ) {
    const { message, signature } = body;
    const siweMessage = new SiweMessage(message);
    const fields = await siweMessage.verify({ signature });

    if (fields.data.nonce !== session.nonce)
      return res.status(422).json({ message: 'Invalid nonce.' });

    session.siwe = fields;
    res.json({ ok: true });
  }

  @Get('/auth/logOut')
  async logOut(@Res() res: Response, @Session() session: Record<string, any>) {
    session.destroy();
    res.send({ ok: true });
  }
}
