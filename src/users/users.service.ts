import { Injectable, HttpException, HttpStatus } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./entities/user.entity";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const existing = await this.userRepository.findOne({
      where: { email: createUserDto.email },
    });
    if (existing) {
      throw new HttpException("User already exists", HttpStatus.CONFLICT);
    }

    const user = this.userRepository.create({
      fullName: createUserDto.fullName,

      email: createUserDto.email,

      twoFactorEnabled: createUserDto.twoFactorEnabled ?? false,
      isEmailVerified: false,
    });
    return this.userRepository.save(user);
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException("User not found", HttpStatus.NOT_FOUND);
    }

    Object.assign(user, {
      fullName: updateUserDto.fullName,

      email: updateUserDto.email,
      ...(updateUserDto.twoFactorEnabled !== undefined && {
        twoFactorEnabled: updateUserDto.twoFactorEnabled,
      }),
    });

    return this.userRepository.save(user);
  }

  async delete(id: number): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException("User not found", HttpStatus.NOT_FOUND);
    }

    await this.userRepository.delete(id);
    return { message: "User deleted successfully" };
  }

  async findById(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException("User not found", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async markEmailVerified(userId: number): Promise<void> {
    await this.userRepository.update(userId, { isEmailVerified: true });
  }

  async isEmailVerified(userId: number): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    return user?.isEmailVerified ?? false;
  }
}
