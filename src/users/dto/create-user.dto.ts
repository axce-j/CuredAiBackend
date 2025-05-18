import { IsNotEmpty, IsString, IsEmail, IsOptional, IsEnum, IsBoolean } from 'class-validator';
import { Expose } from 'class-transformer';
import { Role } from '../enums/roles.enum';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  @Expose()
  firstName: string;
  
  @IsNotEmpty()
  @IsString()
  @Expose()
  middleName: string;
  
  @IsNotEmpty()
  @IsString()
  @Expose()
  otherNames: string;

  @IsEmail()
  @Expose()
  email: string;
  
  @IsNotEmpty()
  @IsString()
  @Expose()
  password: string;
  
  @IsOptional()
  @IsString()
  @Expose()
  image?: string;
  
  @IsEnum(Role)
  @Expose()
  role: Role;

  // Role-specific fields:
  @IsOptional()
  @IsString()
  @Expose()
  matriculationId?: string; // for STUDENT
  
  @IsOptional()
  @IsString()
  @Expose()
  staffId?: string; // for LECTURER (or ADMIN if desired)
  
  // Two-Factor Authentication flag
  @IsOptional()
  @IsBoolean()
  @Expose()
  twoFactorEnabled?: boolean;  
}
