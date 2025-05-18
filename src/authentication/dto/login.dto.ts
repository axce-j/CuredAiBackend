import { IsNotEmpty, IsString, IsOptional, IsEmail } from 'class-validator';

export class LoginDto {
  @IsOptional()
  @IsString()
  matriculationId?: string;

  @IsOptional()
  @IsString()
  staffId?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
