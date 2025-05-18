import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthenticationService } from './authentication.service';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly authenticationService: AuthenticationService,
    private readonly usersService: UsersService
  ) {
    super({
      usernameField: 'identifier',
      passwordField: 'password',
      passReqToCallback: true,
    });
  }

  async validate(req: any, _identifier: string, password: string): Promise<User> {
    // Extract potential identifiers directly from the request body.
    const { email, matriculationId, staffId } = req.body;
    const loginDto = { email, matriculationId, staffId, password };
    const userOr2FAResponse = await this.authenticationService.authenticateUser(loginDto);
    
    // If 2FA is required, throw a custom UnauthorizedException with userId
    if ('requiresTwoFactor' in userOr2FAResponse) {
      // Create a type-safe response object
      const responseObj = {
        message: '2FA Required',
        requiresTwoFactor: true,
        userId: userOr2FAResponse.userId,
        statusCode: 401
      };
      
      // Use the object description as the message and pass the object as the response
      throw new UnauthorizedException(responseObj);
    }
    
    // Fetch full User entity if needed
    const fullUser = await this.usersService.findById(userOr2FAResponse.id);
    if (!fullUser) {
      throw new UnauthorizedException('User not found');
    }
    
    return fullUser;
  }
}