import { IsOptional, IsString } from 'class-validator';

export class RegisterBiometricDto {
  @IsOptional()
  @IsString()
  faceId?: string;

  @IsOptional()
  @IsString()
  fingerprintId?: string;

  @IsOptional()
  @IsString()
  biometricKey?: string; // Added field for storing public key
}
