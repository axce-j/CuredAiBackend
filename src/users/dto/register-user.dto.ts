import { Expose } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsStrongPassword,
  IsEnum,
} from 'class-validator';

// Define the Role enum for better maintainability
export enum Role {
  SUPERADMIN = 'SUPERADMIN',
  STUDENT = 'STUDENT',
  LECTURER = 'LECTURER',
}

export class RegistrationDto {
  @IsNotEmpty()
  @IsString()
  @Expose()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @Expose()
  otherNames: string;

  @IsEmail()
  @Expose()
  email: string;

  @IsStrongPassword()
  @Expose()
  password: string;

  @IsOptional()
  @IsString()
  @Expose()
  city?: string;

  @IsOptional()
  @IsString()
  @Expose()
  tel?: string;

  @IsOptional()
  @IsString()
  @Expose()
  institutionalEmail?: string; // For STUDENT and LECTURER

  @IsOptional()
  @IsString()
  @Expose()
  matriculationId?: string; // For STUDENT

  @IsOptional()
  @IsString()
  @Expose()
  staffId?: string; // For LECTURER

  // @IsOptional()
  // @IsString()
  // @Expose()
  // biometricKey?: string; // For STUDENT

  @IsEnum(Role) // Use the Role enum for validation
  @Expose()
  role: Role; // To define the role
}
