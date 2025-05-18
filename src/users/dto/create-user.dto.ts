import { IsNotEmpty, IsString, IsEmail, IsOptional, IsEnum, IsBoolean } from 'class-validator';
import { Expose } from 'class-transformer';
import { Role } from '../enums/roles.enum';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  @Expose()
  fullName: string;
  
 

  @IsEmail()
  @Expose()
  email: string;
  
  @IsNotEmpty()
  @IsString()
  @Expose()
  password: string;
  
  
 

  
  // Two-Factor Authentication flag
  @IsOptional()
  @IsBoolean()
  @Expose()
  twoFactorEnabled?: boolean;  
}
