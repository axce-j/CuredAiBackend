// import { AuthService } from './auth.service';
// import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
// import { UsersService } from 'src/users/users.service';
// import * as bcrypt from 'bcrypt';
// import { TokenPayload } from './tokenPayload.interface';
// import { JwtService } from '@nestjs/jwt';
// import { ConfigService } from '@nestjs/config';
// import { CreateUserDto } from 'src/users/dto/create-user.dto';
// import { EmailService } from './email.service';

// @Injectable()
// export class AuthenticationService {
//   // In-memory OTP stores (for email confirmation and 2FA)
//   private emailOtpStore = new Map<number, { otp: string; expiresAt: Date }>();
//   private twoFactorOtpStore = new Map<number, { otp: string; expiresAt: Date }>();

//   constructor(
//     private readonly usersService: UsersService,
//     private readonly jwtService: JwtService,
//     private readonly configService: ConfigService,
//     private readonly authService: AuthService,
//     private readonly emailService: EmailService, // For sending OTP emails
//   ) {}

//   // ---------------------
//   // Registration & Email Confirmation
//   // ---------------------
//   public async registerUser(registerDto: CreateUserDto) {
//     try {
//       // Hash the password
//       const hashedPassword = await bcrypt.hash(registerDto.password, 10);
  
//       // Create the user (without storing the password directly)
//       const createdUser = await this.usersService.create({
//         ...registerDto,
//         password: undefined,
//       });
  
//       // Store authentication details separately
//       await this.authService.saveAuthRecord(createdUser.id, hashedPassword);
  
//       // Generate OTP for email confirmation
//       const otp = this.emailService.generateOTP();
//       const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry
//       this.emailOtpStore.set(createdUser.id, { otp, expiresAt });
  
//       // Send OTP via email
//       await this.emailService.sendOtpEmail(createdUser.email, otp);
  
//       return {
//         message: 'User registered successfully. Please verify your email using the OTP sent.',
//         userId: createdUser.id,
//       };
//     } catch (error) {
//       console.error('Error in registerUser:', error);
//       throw new HttpException('Registration failed. Please try again later.', HttpStatus.INTERNAL_SERVER_ERROR);
//     }
//   }
  
  
//   public async verifyEmail(userId: number, otp: string) {
//     const record = this.emailOtpStore.get(userId);
//     if (!record) {
//       throw new HttpException('No OTP found for this user', HttpStatus.BAD_REQUEST);
//     }
//     if (record.expiresAt < new Date()) {
//       this.emailOtpStore.delete(userId);
//       throw new HttpException('OTP expired', HttpStatus.BAD_REQUEST);
//     }
//     if (record.otp !== otp) {
//       throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
//     }
//     // Optionally update the user record to mark email as verified here.
//     this.emailOtpStore.delete(userId);
//     return { message: 'Email verified successfully' };
//   }
  
//   // ---------------------
//   // Login and Optional 2FA
//   // ---------------------
//   /**
//    * Authenticate a user by any identifier (email, matriculationId, or staffId).
//    * If 2FA is enabled (assumed as baseUser.twoFactorEnabled), a 2FA OTP is generated
//    * and sent via email, and an object indicating 2FA is required is returned.
//    */
//   public async authenticateUser(loginDto: { matriculationId?: string; staffId?: string; email?: string; password: string; }) {
//     let authUserView;
//     // Determine which identifier is provided and search by that field.
//     if (loginDto.matriculationId) {
//       authUserView = await this.usersService.findByAuthIdentifier(loginDto.matriculationId, 'matriculationId');
//     } else if (loginDto.staffId) {
//       authUserView = await this.usersService.findByAuthIdentifier(loginDto.staffId, 'staffId');
//     } else if (loginDto.email) {
//       authUserView = await this.usersService.findByAuthIdentifier(loginDto.email, 'email');
//     }
    
//     if (!authUserView) {
//       throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
//     }
    
//     // Fetch the full user profile
//     const baseUser = await this.usersService.findById(authUserView.id);
//     if (!baseUser) {
//       throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
//     }
    
//     // Fetch authentication details (password)
//     const authRecord = await this.authService.findByUserId(baseUser.id);
//     if (!authRecord) {
//       throw new HttpException('Authentication record not found', HttpStatus.UNAUTHORIZED);
//     }
    
//     // Verify password
//     await this.verifyPassword(loginDto.password, authRecord.password);
    
//     // Check if 2FA is enabled for the user (assumed property on User)
//     if (baseUser['twoFactorEnabled']) {
//       // Generate OTP for 2FA
//       const otp = this.emailService.generateOTP();
//       const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // Valid for 10 minutes
//       this.twoFactorOtpStore.set(baseUser.id, { otp, expiresAt });
    
//       // Send OTP via email
//       await this.emailService.sendOtpEmail(baseUser.email, otp);
    
//       return { message: '2FA OTP sent to your email. Please verify to complete login.', requiresTwoFactor: true, userId: baseUser.id };
//     }
    
//     // If 2FA is not enabled, return the user object merged with extra view data.
//     return { ...baseUser, matriculationId: authUserView.matriculationId, staffId: authUserView.staffId };
//   }
  
//   /**
//    * Verify the 2FA OTP for a given user.
//    * If valid, return the full user record (merged with extra view data).
//    */
//   public async verifyTwoFactorCode(userId: number, otp: string) {
//     const record = this.twoFactorOtpStore.get(userId);
//     if (!record) {
//       throw new HttpException('No 2FA code found for this user', HttpStatus.BAD_REQUEST);
//     }
//     if (record.expiresAt < new Date()) {
//       this.twoFactorOtpStore.delete(userId);
//       throw new HttpException('2FA code expired', HttpStatus.BAD_REQUEST);
//     }
//     if (record.otp !== otp) {
//       throw new HttpException('Invalid 2FA code', HttpStatus.BAD_REQUEST);
//     }
//     this.twoFactorOtpStore.delete(userId);
//     // Retrieve base user and merge with view data.
//     const baseUser = await this.usersService.findById(userId);
//     const authUserView = await this.usersService.findByAuthIdentifier(baseUser.email);
//     if (!authUserView) {
//       throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
//     }
//     return { ...baseUser, matriculationId: authUserView.matriculationId, staffId: authUserView.staffId };
//   }
  
//   /**
//    * Resend the 2FA OTP via email for the given user.
//    */
//   public async resendTwoFactorCode(userId: number) {
//     const baseUser = await this.usersService.findById(userId);
//     if (!baseUser) {
//       throw new HttpException('User not found', HttpStatus.NOT_FOUND);
//     }
  
//     // Generate new OTP
//     const otp = this.emailService.generateOTP();
//     const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
//     this.twoFactorOtpStore.set(userId, { otp, expiresAt });
  
//     // Send OTP via email
//     await this.emailService.sendOtpEmail(baseUser.email, otp);
  
//     return { message: 'New 2FA OTP sent to your email.' };
//   }
  
//   private async verifyPassword(plaintextPassword: string, hashedPassword: string) {
//     const isMatch = await bcrypt.compare(plaintextPassword, hashedPassword);
//     if (!isMatch) {
//       throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
//     }
//   }
  
//   // ---------------------
//   // Token Management
//   // ---------------------
//   public getCookieWithJwtToken(id: number, role: string, matriculationId?: string, staffId?: string) {
//     const payload: TokenPayload = { id, role, matriculationId, staffId };
//     const token = this.jwtService.sign(payload);
//     return `Authentication=${token}; Path=/; Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}; SameSite=None`;
//   }
  
//   public logoutByRemovingJwtToken() {
//     return `Authentication=; HttpOnly; Path=/; Age=0`;
//   }
  
//   public async validateToken(token: string): Promise<{
//     isValid: boolean;
//     userId?: string;
//     role?: string;
//     email?: string;
//     matriculationId?: string;
//     staffId?: string;
//   }> {
//     try {
//       const payload: TokenPayload = this.jwtService.verify(token, {
//         secret: this.configService.get<string>('JWT_SECRET'),
//       });
//       let authUser = null;
//       if (payload.matriculationId) {
//         authUser = await this.usersService.findByAuthIdentifier(payload.matriculationId);
//       } else if (payload.staffId) {
//         authUser = await this.usersService.findByAuthIdentifier(payload.staffId);
//       } else if (payload.email) {
//         authUser = await this.usersService.findByAuthIdentifier(payload.email);
//       }
//       if (!authUser) {
//         return { isValid: false };
//       }
//       return {
//         isValid: true,
//         userId: authUser.id.toString(),
//         role: authUser.role,
//         email: authUser.email,
//         matriculationId: authUser.matriculationId ?? undefined,
//         staffId: authUser.staffId ?? undefined,
//       };
//     } catch (error) {
//       return { isValid: false };
//     }
//   }
// }


import { AuthService } from './auth.service';
import { Injectable, HttpException, HttpStatus, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { TokenPayload } from './tokenPayload.interface';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { EmailService } from './email.service';
import { AuthenticationResponse } from './dto/authentication-response.types';

@Injectable()
export class AuthenticationService {
  // In-memory OTP stores (for email confirmation and 2FA)
  private emailOtpStore = new Map<number, { otp: string; expiresAt: Date }>();
  private twoFactorOtpStore = new Map<number, { otp: string; expiresAt: Date }>();
  // In-memory timers for deleting unverified users
  private pendingDeletionTimers = new Map<number, NodeJS.Timeout>();

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly emailService: EmailService, // For sending OTP emails
  ) {}

  // ---------------------
  // Registration & Email Confirmation
  // ---------------------
  public async registerUser(registerDto: CreateUserDto) {
    try {
      // Check if a user with this email already exists
      const existingUser = await this.usersService.findByEmail(registerDto.email);
      if (existingUser) {
        if (!existingUser.isEmailVerified) {
          // User exists but email not verified: resend OTP & reset deletion timer
          const otp = this.emailService.generateOTP();
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry
          this.emailOtpStore.set(existingUser.id, { otp, expiresAt });

          await this.emailService.sendOtpEmail(existingUser.email, otp);

          // Clear any existing deletion timer
          const existingTimer = this.pendingDeletionTimers.get(existingUser.id);
          if (existingTimer) {
            clearTimeout(existingTimer);
            this.pendingDeletionTimers.delete(existingUser.id);
          }

          // Set a new deletion timer to remove unverified user after 10 minutes
          const deletionTimeout = setTimeout(async () => {
            const isVerified = await this.usersService.isEmailVerified(existingUser.id);
            if (!isVerified) {
              console.log(`Deleting unverified user with ID ${existingUser.id}`);
              await this.authService.deleteAuthRecord(existingUser.id);
              await this.usersService.deleteById(existingUser.id);
              this.emailOtpStore.delete(existingUser.id);
            }
            this.pendingDeletionTimers.delete(existingUser.id);
          }, 10 * 60 * 1000);
          this.pendingDeletionTimers.set(existingUser.id, deletionTimeout);

          return {
            message: 'Confirm OTP to complete registration',
            userId: existingUser.id,
          };
        } else {
          throw new HttpException('Email already exists', HttpStatus.CONFLICT);
        }
      }

      // User does not exist: continue with registration

      // Hash the password
      const hashedPassword = await bcrypt.hash(registerDto.password, 10);

      // Create the user (password is not stored directly)
      const createdUser = await this.usersService.create({
        ...registerDto,
        password: undefined,
      });

      // Store authentication details separately
      await this.authService.saveAuthRecord(createdUser.id, hashedPassword);

      // Generate OTP for email confirmation
      const otp = this.emailService.generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry
      this.emailOtpStore.set(createdUser.id, { otp, expiresAt });

      // Send OTP via email
      await this.emailService.sendOtpEmail(createdUser.email, otp);

      // Set deletion timer to remove unverified user after 10 minutes
      const deletionTimeout = setTimeout(async () => {
        const isVerified = await this.usersService.isEmailVerified(createdUser.id);
        if (!isVerified) {
          console.log(`Deleting unverified user with ID ${createdUser.id}`);
          await this.authService.deleteAuthRecord(createdUser.id);
          await this.usersService.deleteById(createdUser.id);
          this.emailOtpStore.delete(createdUser.id);
        }
        this.pendingDeletionTimers.delete(createdUser.id);
      }, 10 * 60 * 1000);
      this.pendingDeletionTimers.set(createdUser.id, deletionTimeout);

      return {
        message: 'User registered successfully. Please verify your email using the OTP sent.',
        userId: createdUser.id,
      };
    } catch (error) {
      console.error('Error in registerUser:', error);
      throw new HttpException('Registration failed. Please try again later.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
  
  public async verifyEmail(userId: number, otp: string) {
    const record = this.emailOtpStore.get(userId);
    if (!record) {
      throw new HttpException('No OTP found for this user', HttpStatus.BAD_REQUEST);
    }
    if (record.expiresAt < new Date()) {
      this.emailOtpStore.delete(userId);
      throw new HttpException('OTP expired', HttpStatus.BAD_REQUEST);
    }
    if (record.otp !== otp) {
      throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }
    
    // Mark the user's email as verified
    await this.usersService.markEmailVerified(userId);

    // Remove the OTP record
    this.emailOtpStore.delete(userId);

    // Cancel the pending deletion timer if it exists
    const timer = this.pendingDeletionTimers.get(userId);
    if (timer) {
      clearTimeout(timer);
      this.pendingDeletionTimers.delete(userId);
    }
  
    return { message: 'Email verified successfully' };
  }
  
  // ---------------------
  // Login and Optional 2FA
  // ---------------------
  public async authenticateUser(loginDto: {
    matriculationId?: string;
    staffId?: string;
    email?: string;
    password: string;
  }): Promise<AuthenticationResponse> {
    let authUserView;
  
    if (loginDto.matriculationId) {
      authUserView = await this.usersService.findByAuthIdentifier(
        loginDto.matriculationId,
        'matriculationId'
      );
    } else if (loginDto.staffId) {
      authUserView = await this.usersService.findByAuthIdentifier(
        loginDto.staffId,
        'staffId'
      );
    } else if (loginDto.email) {
      authUserView = await this.usersService.findByAuthIdentifier(
        loginDto.email,
        'email'
      );
    }
  
    if (!authUserView) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  
    const baseUser = await this.usersService.findById(authUserView.id);
    if (!baseUser) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  
    const authRecord = await this.authService.findByUserId(baseUser.id);
    if (!authRecord) {
      throw new HttpException(
        'Authentication record not found',
        HttpStatus.UNAUTHORIZED
      );
    }
  
    await this.verifyPassword(loginDto.password, authRecord.password);
  
    // ✅ 2FA Enabled – send OTP and return partial response
    if (baseUser.twoFactorEnabled) {
      const otp = this.emailService.generateOTP();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
      this.twoFactorOtpStore.set(baseUser.id, { otp, expiresAt });
    
      await this.emailService.sendOtpEmail(baseUser.email, otp);
    
      // ❌ Old: just returned a response
      // ✅ New: throw UnauthorizedException with correct shape
      throw new UnauthorizedException({
        statusCode: 401,
        message: '2FA Required',
        requiresTwoFactor: true,
        userId: baseUser.id,
        role: baseUser.role, // ✅ Now included!
      });
    }
    
  
    // ✅ Auth success – return full user object + auth identifiers
    return {
      ...baseUser,
      matriculationId: authUserView.matriculationId,
      staffId: authUserView.staffId,
    };
  }
  
  
  
  public async verifyTwoFactorCode(userId: number, otp: string) {
    const record = this.twoFactorOtpStore.get(userId);
    if (!record) {
      throw new HttpException('No 2FA code found for this user', HttpStatus.BAD_REQUEST);
    }
    if (record.expiresAt < new Date()) {
      this.twoFactorOtpStore.delete(userId);
      throw new HttpException('2FA code expired', HttpStatus.BAD_REQUEST);
    }
    if (record.otp !== otp) {
      throw new HttpException('Invalid 2FA code', HttpStatus.BAD_REQUEST);
    }
    this.twoFactorOtpStore.delete(userId);
    
    const baseUser = await this.usersService.findById(userId);
    const authUserView = await this.usersService.findByAuthIdentifier(baseUser.email);
    if (!authUserView) {
      throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
    }
    return { ...baseUser, matriculationId: authUserView.matriculationId, staffId: authUserView.staffId };
  }
  
  public async resendTwoFactorCode(userId: number) {
    const baseUser = await this.usersService.findById(userId);
    if (!baseUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  
    const otp = this.emailService.generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    this.twoFactorOtpStore.set(userId, { otp, expiresAt });
  
    await this.emailService.sendOtpEmail(baseUser.email, otp);
  
    return { message: 'New 2FA OTP sent to your email.' };
  }
  
  private async verifyPassword(plaintextPassword: string, hashedPassword: string) {
    const isMatch = await bcrypt.compare(plaintextPassword, hashedPassword);
    if (!isMatch) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }
  
  // ---------------------
  // Token Management
  // ---------------------
  public getCookieWithJwtToken(id: number, role: string, matriculationId?: string, staffId?: string) {
    const payload: TokenPayload = { id, role, matriculationId, staffId };
    const token = this.jwtService.sign(payload);
    return `Authentication=${token}; Path=/; Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}; SameSite=None`;
  }
  
  public logoutByRemovingJwtToken() {
    return `Authentication=; HttpOnly; Path=/; Age=0`;
  }
  
  public async validateToken(token: string): Promise<{
    isValid: boolean;
    userId?: string;
    role?: string;
    email?: string;
    matriculationId?: string;
    staffId?: string;
  }> {
    try {
      const payload: TokenPayload = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
      let authUser = null;
      if (payload.matriculationId) {
        authUser = await this.usersService.findByAuthIdentifier(payload.matriculationId);
      } else if (payload.staffId) {
        authUser = await this.usersService.findByAuthIdentifier(payload.staffId);
      } else if (payload.email) {
        authUser = await this.usersService.findByAuthIdentifier(payload.email);
      }
      if (!authUser) {
        return { isValid: false };
      }
      return {
        isValid: true,
        userId: authUser.id.toString(),
        role: authUser.role,
        email: authUser.email,
        matriculationId: authUser.matriculationId ?? undefined,
        staffId: authUser.staffId ?? undefined,
      };
    } catch (error) {
      return { isValid: false };
    }
  }
}
