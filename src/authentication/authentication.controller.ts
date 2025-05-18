// import { AuthenticationService } from "./authentication.service";
// import { CreateUserDto } from "src/users/dto/create-user.dto";
// import {
//   Body,
//   Controller,
//   Get,
//   HttpCode,
//   HttpException,
//   HttpStatus,
//   Post,
//   Req,
//   Res,
//   UseGuards,
//   UseInterceptors,
//   ClassSerializerInterceptor,
//   SerializeOptions,
// } from "@nestjs/common";
// import { LocalAuthenticationGuard } from "./localAuthenticationGuard";
// import { Response } from "express";
// import { JwtAuthenticationGuard } from "./jwtAuthenticationGuard";
// import { LoginDto } from "./dto/login.dto";
// import { ApiBody, ApiTags } from "@nestjs/swagger";
// import { TwoFactorDto } from "./dto/twoFactor.dto";
// import { RequestWithUser } from "./requestWithUSer";

// @Controller("authentication")
// @ApiTags("authentication")
// export class AuthenticationController {
//   constructor(private readonly authenticationService: AuthenticationService) {}

//   // demo body
//   // {
//   //   "firstName": "Alice",
//   //   "lastName": "Smith",
//   //   "email": "alice@example.com",
//   //   "password": "StrongP@ssw0rd!",
//   //   "role": "STUDENT",
//   //   "matriculationId": "STU12345"
//   // "twoFactorEnabled": false
//   //
//   // }
//   @UseInterceptors(ClassSerializerInterceptor)
//   @Post("register")
//   async register(@Body() registerData: CreateUserDto) {
//     return this.authenticationService.registerUser(registerData);
//   }

//   // demo body
//   // {
//   //   "userId": 1,
//   //   "otp": "the_received_otp"
//   // }
//   @Post("verify-email")
//   async verifyEmail(@Body() body: { userId: number; otp: string }) {
//     return this.authenticationService.verifyEmail(body.userId, body.otp);
//   }

//   // demo body
//   // {
//   //   "matriculationId": "22/0162",
//   //   "password": "Introduction12@",
//   //   "identifier": "22/0163"
//   // }
//   // or
//   // {
//   //   "email": "johnobi699@gmail.com",
//   //   "password": "Introduction12@",
//   //   "identifier": "johnobi699@gmail.com"
//   // }

//   @HttpCode(200)
//   @UseGuards(LocalAuthenticationGuard)
//   @UseInterceptors(ClassSerializerInterceptor)
//   @Post("log-in")
//   @ApiBody({ type: LoginDto })
//   async logIn(@Body() payload: LoginDto, @Req() request: any) {
//     const result = await this.authenticationService.authenticateUser(payload);

//     if ("message" in result && "userId" in result) {
//       // 2FA is required
//       return { message: result.message, userId: result.userId };
//     } else {
//       const user = result;
//       const cookie = this.authenticationService.getCookieWithJwtToken(
//         user.id,
//         user.role,
//         user.matriculationId,
//         user.staffId
//       );
//       request.res.setHeader("Set-Cookie", cookie);
//       return user;
//     }
//   }

//   // demo body
//   // {
//   //   "userId": 1,
//   //   "otp": "the_2fa_otp"
//   // }
//   @HttpCode(200)
//   @Post("verify-2fa")
//   async verifyTwoFactor(
//     @Body() twoFactorDto: TwoFactorDto,
//     @Req() request: any
//   ) {
//     const user = await this.authenticationService.verifyTwoFactorCode(
//       twoFactorDto.userId,
//       twoFactorDto.otp
//     );
//     const cookie = this.authenticationService.getCookieWithJwtToken(
//       user.id,
//       user.role,
//       user.matriculationId,
//       user.staffId
//     );
//     request.res.setHeader("Set-Cookie", cookie);
//     return user;
//   }

//   // demo body
//   // {
//   //   "userId": 1
//   // }
//   // New endpoint for resending 2FA OTP
//   @HttpCode(200)
//   @Post("resend-2fa")
//   async resendTwoFactor(@Body() body: { userId: number }, @Req() request: any) {
//     const result = await this.authenticationService.resendTwoFactorCode(
//       body.userId
//     );
//     return result;
//   }



//   // ensure the authenticated cookie is passed in the header for this to work
//   @UseGuards(JwtAuthenticationGuard)
//   @UseInterceptors(ClassSerializerInterceptor)
//   @Get("profile")
//   @SerializeOptions({
//     strategy: "excludeAll",
//   })
//   authenticate(@Req() request: RequestWithUser) {
//     const { user } = request;
//     if (!user) {
//       throw new HttpException("User not found", HttpStatus.UNAUTHORIZED);
//     }
//     return user;
//   }

//   @UseGuards(JwtAuthenticationGuard)
//   @Post("log-out")
//   async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
//     response.setHeader(
//       "Set-Cookie",
//       this.authenticationService.logoutByRemovingJwtToken()
//     );
//     response.sendStatus(200);
//   }

//   @Post("validate-token")
//   async validateToken(@Body() body: { token: string }) {
//     if (!body.token) {
//       throw new HttpException("Token is required", HttpStatus.BAD_REQUEST);
//     }
//     const validationResult = await this.authenticationService.validateToken(
//       body.token
//     );
//     if (!validationResult.isValid) {
//       throw new HttpException("Invalid token", HttpStatus.UNAUTHORIZED);
//     }
//     return validationResult;
//   }
// }





  import { AuthenticationService } from "./authentication.service";
  import { CreateUserDto } from "src/users/dto/create-user.dto";
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
    SerializeOptions,
    UnauthorizedException,
  } from "@nestjs/common";
  import { LocalAuthenticationGuard } from "./localAuthenticationGuard";
  import { Response } from "express";
  import { JwtAuthenticationGuard } from "./jwtAuthenticationGuard";
  import { LoginDto } from "./dto/login.dto";
  import { ApiBody, ApiTags } from "@nestjs/swagger";
  import { TwoFactorDto } from "./dto/twoFactor.dto";
  import { RequestWithUser } from "./requestWithUSer";
import { AuthenticatedUser } from "./dto/authentication-response.types";

  @Controller("authentication")
  @ApiTags("authentication")
  export class AuthenticationController {
    constructor(private readonly authenticationService: AuthenticationService) {}

    @UseInterceptors(ClassSerializerInterceptor)
    @Post("register")
    async register(@Body() registerData: CreateUserDto) {
      return this.authenticationService.registerUser(registerData);
    }

    @Post("verify-email")
    async verifyEmail(@Body() body: { userId: number; otp: string }) {
      return this.authenticationService.verifyEmail(body.userId, body.otp);
    }

    @HttpCode(200)
    @UseGuards(LocalAuthenticationGuard)
    @UseInterceptors(ClassSerializerInterceptor)
    @Post("log-in")
    @ApiBody({ type: LoginDto })
    async logIn(@Body() payload: LoginDto, @Req() request: any) {
      try {
        // This will contain the full User from the strategy
        const user = request.user;
        // Create a sanitized user response by omitting sensitive fields
        const sanitizedUser = {
          id: user.id,
          firstName: user.firstName,
          middleName: user.middleName,
          otherNames: user.otherNames,
          role: user.role,
          email: user.email,
          matriculationId: user.matriculationId,
          staffId: user.staffId,
          twoFactorEnabled: user.twoFactorEnabled,
        };
        
        const cookie = this.authenticationService.getCookieWithJwtToken(
          user.id,
          user.role,
          user.matriculationId,
          user.staffId
        );
        request.res.setHeader("Set-Cookie", cookie);
        
        // Return the sanitized user object
        return sanitizedUser;
      } catch (error) {
        // Handle the 2FA exception
        if (error instanceof UnauthorizedException) {
          const response = error.getResponse();
          
          // Check if response is an object and has requiresTwoFactor property
          if (typeof response === 'object' && 
              response !== null && 
              'requiresTwoFactor' in response) {
            
            // Type assertion to tell TypeScript about the properties we expect
            const twoFactorResponse = response as {
              message: string;
              requiresTwoFactor: boolean;
              userId: number;
              role:string;
              statusCode: number;
            };
            
            // Return a successful response with 2FA info  
            return {
              statusCode: 200,  // Override to 200 since this is an expected flow
              message: twoFactorResponse.message,
              requiresTwoFactor: true,
              userId: twoFactorResponse.userId,
              role: twoFactorResponse.role,
            };
          }
        }
        
        // If another error occurred, throw it to be handled elsewhere
        throw error;
      }
    }

    
    @HttpCode(200)
    @Post("verify-2fa")
    async verifyTwoFactor(
      @Body() twoFactorDto: TwoFactorDto,
      @Req() request: any
    ) {
      const user = await this.authenticationService.verifyTwoFactorCode(
        twoFactorDto.userId,
        twoFactorDto.otp
      );
      const cookie = this.authenticationService.getCookieWithJwtToken(
        user.id,
        user.role,
        user.matriculationId,
        user.staffId
      );
      request.res.setHeader("Set-Cookie", cookie);
      return user;
    }

    @HttpCode(200)
    @Post("resend-2fa")
    async resendTwoFactor(@Body() body: { userId: number }, @Req() request: any) {
      const result = await this.authenticationService.resendTwoFactorCode(body.userId);
      return result;
    }

    @UseGuards(JwtAuthenticationGuard)
    @UseInterceptors(ClassSerializerInterceptor)
    @Get("profile")
    @SerializeOptions({
      strategy: "excludeAll",
    })
    authenticate(@Req() request: RequestWithUser) {
      const { user } = request;
      if (!user) {
        throw new HttpException("User not found", HttpStatus.UNAUTHORIZED);
      }
      return user;
    }

    @UseGuards(JwtAuthenticationGuard)
    @Post("log-out")
    async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
      response.setHeader(
        "Set-Cookie",
        this.authenticationService.logoutByRemovingJwtToken()
      );
      response.sendStatus(200);
    }

    @Post("validate-token")
    async validateToken(@Body() body: { token: string }) {
      if (!body.token) {
        throw new HttpException("Token is required", HttpStatus.BAD_REQUEST);
      }
      const validationResult = await this.authenticationService.validateToken(body.token);
      if (!validationResult.isValid) {
        throw new HttpException("Invalid token", HttpStatus.UNAUTHORIZED);
      }
      return validationResult;
    }
  }
