import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Response, Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = new this.userModel({
      username: dto.username,
      email: dto.email,
      password: hashedPassword,
    });
    await user.save();
    return { message: 'User registered successfully' };
  }

  async login(dto: LoginDto, res: Response) {
    const user = await this.userModel.findOne({ email: dto.email });
    if (!user || !(await bcrypt.compare(dto.password, user.password))) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const accessToken = this.jwtService.sign(
      { sub: user._id },
      {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );

    const refreshToken = this.jwtService.sign(
      { sub: user._id },
      {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );

    user.refreshToken = await bcrypt.hash(refreshToken, 10);
    await user.save();

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000, // 15 mins
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: 'Logged in successfully' });
  }

  async refresh(req: Request, res: Response) {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) throw new ForbiddenException('No refresh token found');

    let payload: any;
    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (e) {
      throw new ForbiddenException('Invalid refresh token');
    }

    const user = await this.userModel.findById(payload.sub);
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('User not found or no refresh token stored');
    }

    const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!isMatch) {
      throw new ForbiddenException('Refresh token mismatch');
    }

    const newAccessToken = this.jwtService.sign(
      { sub: user._id },
      {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      },
    );

    const newRefreshToken = this.jwtService.sign(
      { sub: user._id },
      {
        secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      },
    );

    user.refreshToken = await bcrypt.hash(newRefreshToken, 10);
    await user.save();

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { message: 'Access token refreshed' };
  }

  async logout(req: Request, res: Response) {
    const refreshToken = req.cookies?.refresh_token;

    if (refreshToken) {
      try {
        const payload: any = this.jwtService.verify(refreshToken, {
          secret: this.config.get<string>('JWT_REFRESH_SECRET'),
        });
        const user = await this.userModel.findById(payload.sub);
        if (user) {
          user.refreshToken = null;
          await user.save();
        }
      } catch (e) {
        console.error('Error during logout:', e);
      }
    }

    res.clearCookie('access_token', { httpOnly: true, sameSite: 'lax' });
    res.clearCookie('refresh_token', { httpOnly: true, sameSite: 'lax' });

    res.json({ message: 'Logged out successfully' });
  }

  async verifyAccessToken(token: string) {
    return this.jwtService.verify(token, {
        secret: this.config.get<string>('JWT_ACCESS_SECRET'),
    });
  }
}
