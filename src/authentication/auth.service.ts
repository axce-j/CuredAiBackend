// import { Injectable } from '@nestjs/common';
// import { InjectRepository } from '@nestjs/typeorm';
// import { Repository } from 'typeorm';
// import { Auth } from './auth.entity';

// @Injectable()
// export class AuthService {
//   constructor(
//     @InjectRepository(Auth)
//     private readonly authRepository: Repository<Auth>,
//   ) {}

//   async findByUserId(userId: number): Promise<Auth | null> {
//     return this.authRepository.findOne({ where: { user: { id: userId } }, relations: ['user'] });
//   }

//   async saveAuthRecord(userId: number, hashedPassword: string): Promise<Auth> {
//     const auth = this.authRepository.create({ user: { id: userId }, password: hashedPassword });
//     return this.authRepository.save(auth);
//   }
// }


import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Auth } from './auth.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth)
    private readonly authRepository: Repository<Auth>,
  ) {}

  async findByUserId(userId: number): Promise<Auth | null> {
    return this.authRepository.findOne({ where: { user: { id: userId } }, relations: ['user'] });
  }

  async saveAuthRecord(userId: number, hashedPassword: string): Promise<Auth> {
    const auth = this.authRepository.create({ user: { id: userId }, password: hashedPassword });
    return this.authRepository.save(auth);
  }

  // New method: Delete the auth record for the given user
  async deleteAuthRecord(userId: number): Promise<void> {
    await this.authRepository.delete({ user: { id: userId } });
  }
}
