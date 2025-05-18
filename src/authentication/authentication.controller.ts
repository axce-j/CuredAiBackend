import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
  ClassSerializerInterceptor,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { Response } from 'express';
import { LocalAuthenticationGuard } from './localAuthenticationGuard';
import { JwtAuthenticationGuard } from './jwtAuthenticationGuard';
import { LoginDto } from './dto/login.dto';
import { TwoFactorDto } from './dto/twoFactor.dto';
import { RequestWithUser } from './requestWithUSer';
import { ApiBody, ApiTags } from '@nestjs/swagger';

@Controller('authentication')
@ApiTags('authentication')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

  @Post('register')
  async register(@Body() data: CreateUserDto) {
    return this.authenticationService.registerUser(data);
  }

  @Post('verify-email')
  async verifyEmail(@Body() body: { userId: number; otp: string }) {
    return this.authenticationService.verifyEmail(body.userId, body.otp);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('log-in')
  @ApiBody({ type: LoginDto })
  async logIn(@Body() _: LoginDto, @Req() req: any) {
    try {
      const user = req.user;
      const cookie = this.authenticationService.getCookieWithJwtToken(user.id);
      req.res.setHeader('Set-Cookie', cookie);
      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException && error.getResponse()['requiresTwoFactor']) {
        return { statusCode: 200, ...(error.getResponse() as object) };
      }
      throw error;
    }
  }

  @Post('verify-2fa')
  async verifyTwoFactor(@Body() dto: TwoFactorDto, @Req() req: any) {
    const user = await this.authenticationService.verifyTwoFactorCode(dto.userId, dto.otp);
    const cookie = this.authenticationService.getCookieWithJwtToken(user.id);
    req.res.setHeader('Set-Cookie', cookie);
    return user;
  }

  @Post('resend-2fa')
  async resendTwoFactor(@Body() body: { userId: number }) {
    return this.authenticationService.resendTwoFactorCode(body.userId);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get('profile')
  @UseInterceptors(ClassSerializerInterceptor)
  authenticate(@Req() req: RequestWithUser) {
    if (!req.user) throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
    return req.user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post('log-out')
  async logOut(@Req() req: RequestWithUser, @Res() res: Response) {
    res.setHeader('Set-Cookie', this.authenticationService.logoutByRemovingJwtToken());
    res.sendStatus(200);
  }

  @Post('validate-token')
  async validateToken(@Body() body: { token: string }) {
    if (!body.token) throw new HttpException('Token is required', HttpStatus.BAD_REQUEST);
    const result = await this.authenticationService.validateToken(body.token);
    if (!result.isValid) throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    return result;
  }
}
