// src/auth/auth.controller.ts
import {
  Body,
  Controller,
  Post,
  Req,
  Res,
  UsePipes,
  ValidationPipe,
} 

from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Request, Response } from 'express';
import { Get } from '@nestjs/common';

@Controller()
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @UsePipes(new ValidationPipe())
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @UsePipes(new ValidationPipe())
  login(@Body() dto: LoginDto, @Res() res: Response) {
    return this.authService.login(dto, res);
  }

  @Post('refresh')
  refresh(@Req() req: Request, @Res() res: Response) {
    return this.authService.refresh(req, res);
  }

  @Post('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    return this.authService.logout(req, res);
  }

  @Get('status')
  async status(@Req() req: Request) {
    const accessToken = req.cookies?.access_token;

    if (!accessToken) {
      return { loggedIn: false };
    }

    try {
        const payload = await this.authService.verifyAccessToken(accessToken);
        return {
            loggedIn: true,
            userId: payload.sub,
        };
    } catch (err) {
        return { loggedIn: false };
    }
  }
}
