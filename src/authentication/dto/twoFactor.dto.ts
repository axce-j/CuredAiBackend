import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class TwoFactorDto {
  @IsNotEmpty()
  @IsNumber()
  userId: number;

  @IsNotEmpty()
  @IsString()
  otp: string;
}
