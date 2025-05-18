import { Injectable, HttpException, HttpStatus, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { UsersService } from 'src/users/users.service';
import { AuthService } from './auth.service';
import { EmailService } from './email.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { TokenPayload } from './tokenPayload.interface';
import { AuthenticationResponse } from './dto/authentication-response.types';

@Injectable()
export class AuthenticationService {
  private emailOtpStore = new Map<number, { otp: string; expiresAt: Date }>();
  private twoFactorOtpStore = new Map<number, { otp: string; expiresAt: Date }>();
  private pendingDeletionTimers = new Map<number, NodeJS.Timeout>();

  constructor(
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  public async registerUser(registerDto: CreateUserDto) {
    try {
      const existingUser = await this.usersService.findByEmail(registerDto.email);
      if (existingUser) {
        if (!existingUser.isEmailVerified) {
          const otp = this.emailService.generateOTP();
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
          this.emailOtpStore.set(existingUser.id, { otp, expiresAt });
          await this.emailService.sendOtpEmail(existingUser.email, otp);

          const existingTimer = this.pendingDeletionTimers.get(existingUser.id);
          if (existingTimer) {
            clearTimeout(existingTimer);
            this.pendingDeletionTimers.delete(existingUser.id);
          }

          const deletionTimeout = setTimeout(async () => {
            const isVerified = await this.usersService.isEmailVerified(existingUser.id);
            if (!isVerified) {
              await this.authService.deleteAuthRecord(existingUser.id);
              await this.usersService.delete(existingUser.id);
              this.emailOtpStore.delete(existingUser.id);
            }
            this.pendingDeletionTimers.delete(existingUser.id);
          }, 10 * 60 * 1000);
          this.pendingDeletionTimers.set(existingUser.id, deletionTimeout);

          return { message: 'Confirm OTP to complete registration', userId: existingUser.id };
        } else {
          throw new HttpException('Email already exists', HttpStatus.CONFLICT);
        }
      }

      const hashedPassword = await bcrypt.hash(registerDto.password, 10);
      const createdUser = await this.usersService.create({ ...registerDto, password: undefined });
      await this.authService.saveAuthRecord(createdUser.id, hashedPassword);

      const otp = this.emailService.generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      this.emailOtpStore.set(createdUser.id, { otp, expiresAt });
      await this.emailService.sendOtpEmail(createdUser.email, otp);

      const deletionTimeout = setTimeout(async () => {
        const isVerified = await this.usersService.isEmailVerified(createdUser.id);
        if (!isVerified) {
          await this.authService.deleteAuthRecord(createdUser.id);
          await this.usersService.delete(createdUser.id);
          this.emailOtpStore.delete(createdUser.id);
        }
        this.pendingDeletionTimers.delete(createdUser.id);
      }, 10 * 60 * 1000);
      this.pendingDeletionTimers.set(createdUser.id, deletionTimeout);

      return { message: 'User registered successfully. Please verify your email using the OTP sent.', userId: createdUser.id };
    } catch (error) {
      console.error('Error in registerUser:', error);
      throw new HttpException('Registration failed', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  public async verifyEmail(userId: number, otp: string) {
    const record = this.emailOtpStore.get(userId);
    if (!record || record.expiresAt < new Date()) {
      this.emailOtpStore.delete(userId);
      throw new HttpException('Invalid or expired OTP', HttpStatus.BAD_REQUEST);
    }

    if (record.otp !== otp) {
      throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }

    await this.usersService.markEmailVerified(userId);
    this.emailOtpStore.delete(userId);
    const timer = this.pendingDeletionTimers.get(userId);
    if (timer) {
      clearTimeout(timer);
      this.pendingDeletionTimers.delete(userId);
    }

    return { message: 'Email verified successfully' };
  }

  public async authenticateUser(loginDto: { email: string; password: string }): Promise<AuthenticationResponse> {
    const user = await this.usersService.findByEmail(loginDto.email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const authRecord = await this.authService.findByUserId(user.id);
    if (!authRecord) throw new UnauthorizedException('No auth record found');

    await this.verifyPassword(loginDto.password, authRecord.password);

    if (user.twoFactorEnabled) {
      const otp = this.emailService.generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      this.twoFactorOtpStore.set(user.id, { otp, expiresAt });
      await this.emailService.sendOtpEmail(user.email, otp);

      throw new UnauthorizedException({
        statusCode: 401,
        message: '2FA Required',
        requiresTwoFactor: true,
        userId: user.id,
      });
    }

    return user;
  }

  public async verifyTwoFactorCode(userId: number, otp: string) {
    const record = this.twoFactorOtpStore.get(userId);
    if (!record || record.expiresAt < new Date() || record.otp !== otp) {
      this.twoFactorOtpStore.delete(userId);
      throw new HttpException('Invalid or expired 2FA code', HttpStatus.BAD_REQUEST);
    }

    this.twoFactorOtpStore.delete(userId);
    return this.usersService.findById(userId);
  }

  public async resendTwoFactorCode(userId: number) {
    const user = await this.usersService.findById(userId);
    const otp = this.emailService.generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    this.twoFactorOtpStore.set(user.id, { otp, expiresAt });
    await this.emailService.sendOtpEmail(user.email, otp);
    return { message: 'New 2FA OTP sent' };
  }

  private async verifyPassword(raw: string, hashed: string) {
    const isMatch = await bcrypt.compare(raw, hashed);
    if (!isMatch) throw new UnauthorizedException('Invalid credentials');
  }

  public getCookieWithJwtToken(id: number) {
    const payload: TokenPayload = { id };
    const token = this.jwtService.sign(payload);
    return `Authentication=${token}; Path=/; Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}; SameSite=None`;
  }

  public logoutByRemovingJwtToken() {
    return 'Authentication=; HttpOnly; Path=/; Age=0';
  }

  public async validateToken(token: string) {
    try {
      const payload = this.jwtService.verify<TokenPayload>(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
      const user = await this.usersService.findById(payload.id);
      if (!user) return { isValid: false };
      return { isValid: true, userId: user.id.toString(), email: user.email };
    } catch {
      return { isValid: false };
    }
  }
}
