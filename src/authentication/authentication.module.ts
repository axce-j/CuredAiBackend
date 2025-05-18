import { Module } from '@nestjs/common';
import { AuthenticationController } from './authentication.controller';
import { AuthenticationService } from './authentication.service';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from './auth.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Auth } from './auth.entity'; // Import the Auth entity

import { UsersModule } from '../users/users.module'; // ✅ Import UsersModule
import { EmailService } from './email.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Auth]),
    PassportModule,
    ConfigModule,
    UsersModule,  // ✅ Ensure UsersModule is imported here
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: `${configService.get('JWT_EXPIRATION_TIME')}s` },
      }),
    }),
  ],
  controllers: [AuthenticationController],
  providers: [AuthenticationService, LocalStrategy, AuthService, EmailService,JwtStrategy],
  exports: [AuthService],
})
export class AuthenticationModule {}

