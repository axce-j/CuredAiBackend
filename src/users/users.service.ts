// import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
// import { InjectRepository } from '@nestjs/typeorm';
// import { Repository } from 'typeorm';
// import { User } from './entities/user.entity';
// import { Student } from './entities/student.entity';
// import { Lecturer } from './entities/lecturer.entity';
// import { Admin } from './entities/admin.entity';
// // import { UserAuthView } from './entities/user-auth.view';
// import { Role } from './enums/roles.enum';
// import { CreateUserDto } from './dto/create-user.dto';
// import { UpdateUserDto } from './dto/update-user.dto';
// import { UserAuthView } from './entities/user.auth.view.entity';

// @Injectable()
// export class UsersService {
//   constructor(
//     @InjectRepository(User)
//     private userRepository: Repository<User>,
//     @InjectRepository(Student)
//     private studentRepository: Repository<Student>,
//     @InjectRepository(Lecturer)
//     private lecturerRepository: Repository<Lecturer>,
//     @InjectRepository(Admin)
//     private adminRepository: Repository<Admin>,
//     @InjectRepository(UserAuthView)
//     private userAuthViewRepository: Repository<UserAuthView>,
//   ) {}

//   async create(createUserDto: CreateUserDto): Promise<User> {
//     // Check if user exists
//     const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
//     if (existing) {
//       throw new HttpException('User already exists', HttpStatus.CONFLICT);
//     }

//     // Create base user
//     const user = this.userRepository.create({
//       firstName: createUserDto.firstName,
//       middleName: createUserDto.middleName,
//       otherNames: createUserDto.otherNames,

//       email: createUserDto.email,
//       image: createUserDto.image,
//       role: createUserDto.role,
//       twoFactorEnabled: createUserDto.twoFactorEnabled ?? false,

//     });
//     const savedUser = await this.userRepository.save(user);

//     // Create role-specific profile
//     switch (createUserDto.role) {
//       case Role.STUDENT:
//         if (!createUserDto.matriculationId) {
//           throw new HttpException('Matriculation ID required for students', HttpStatus.BAD_REQUEST);
//         }
//         const student = this.studentRepository.create({
//           user: savedUser,
//           matriculationId: createUserDto.matriculationId,
//         });
//         await this.studentRepository.save(student);
//         break;
//       case Role.LECTURER_FREE:
//       case Role.LECTURER_BASIC:
//       case Role.LECTURER_PREMIUM:
//         if (!createUserDto.staffId) {
//           throw new HttpException('Staff ID required for lecturers', HttpStatus.BAD_REQUEST);
//         }
//         const lecturer = this.lecturerRepository.create({
//           user: savedUser,
//           staffId: createUserDto.staffId,
//         });
//         await this.lecturerRepository.save(lecturer);
//         break;
//       case Role.ADMIN_FREE:
//       case Role.ADMIN_BASIC:
//       case Role.ADMIN_PREMIUM:
//       case Role.SUPERADMIN:
//         if (!createUserDto.staffId) {
//           throw new HttpException('Staff ID required for admins', HttpStatus.BAD_REQUEST);
//         }
//         const admin = this.adminRepository.create({
//           user: savedUser,
//           adminType: createUserDto.role,
//         });
//         await this.adminRepository.save(admin);
//         break;
//       default:
//         break;
//     }
//     return savedUser;
//   }

//   async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
//     // Retrieve the base user
//     const user = await this.userRepository.findOne({ where: { id } });
//     if (!user) {
//       throw new HttpException('User not found', HttpStatus.NOT_FOUND);
//     }
//     // Update common properties
//     Object.assign(user, {
//       firstName: updateUserDto.firstName,
//       middleName: updateUserDto.middleName,
//       otherNaames: updateUserDto.otherNames,

//       email: updateUserDto.email,
//       image: updateUserDto.image,
//       ...(updateUserDto.twoFactorEnabled !== undefined && { twoFactorEnabled: updateUserDto.twoFactorEnabled }),

      
//     });
//     const updatedUser = await this.userRepository.save(user);

//     // Update role-specific details
//     if (updatedUser.role === Role.STUDENT && updateUserDto.matriculationId) {
//       const studentProfile = await this.studentRepository.findOne({ where: { user: updatedUser } });
//       if (studentProfile) {
//         studentProfile.matriculationId = updateUserDto.matriculationId;
//         await this.studentRepository.save(studentProfile);
//       }
//     }
//     if (
//       (updatedUser.role === Role.LECTURER_FREE ||
//        updatedUser.role === Role.LECTURER_BASIC ||
//        updatedUser.role === Role.LECTURER_PREMIUM) &&
//       updateUserDto.staffId
//     ) {
//       const lecturerProfile = await this.lecturerRepository.findOne({ where: { user: updatedUser } });
//       if (lecturerProfile) {
//         lecturerProfile.staffId = updateUserDto.staffId;
//         await this.lecturerRepository.save(lecturerProfile);
//       }
//     }
//     if (
//       (updatedUser.role === Role.ADMIN_FREE ||
//        updatedUser.role === Role.ADMIN_BASIC ||
//        updatedUser.role === Role.ADMIN_PREMIUM ||
//        updatedUser.role === Role.SUPERADMIN) &&
//       updateUserDto.staffId
//     ) {
//       const adminProfile = await this.adminRepository.findOne({ where: { user: updatedUser } });
//       if (adminProfile) {
//         adminProfile.adminType = updatedUser.role;
//         await this.adminRepository.save(adminProfile);
//       }
//     }
//     return updatedUser;
//   }

//   async delete(id: number): Promise<{ message: string }> {
//     const user = await this.userRepository.findOne({ where: { id } });
//     if (!user) {
//       throw new HttpException('User not found', HttpStatus.NOT_FOUND);
//     }

//     // Delete associated profile depending on role
//     switch (user.role) {
//       case Role.STUDENT:
//         await this.studentRepository.delete({ user });
//         break;
//       case Role.LECTURER_FREE:
//       case Role.LECTURER_BASIC:
//       case Role.LECTURER_PREMIUM:
//         await this.lecturerRepository.delete({ user });
//         break;
//       case Role.ADMIN_FREE:
//       case Role.ADMIN_BASIC:
//       case Role.ADMIN_PREMIUM:
//       case Role.SUPERADMIN:
//         await this.adminRepository.delete({ user });
//         break;
//       default:
//         break;
//     }

//     await this.userRepository.delete(id);
//     return { message: 'User deleted successfully' };
//   }

//   async findById(id: number): Promise<User> {
//     const user = await this.userRepository.findOne({ where: { id } });
//     if (!user) {
//       throw new HttpException('User not found', HttpStatus.NOT_FOUND);
//     }
//     return user;
//   }

//   // New method: use the authentication view to look up a user by any identifier.
//  // In users.service.ts
// async findByAuthIdentifier(identifier: string, field?: 'email' | 'matriculationId' | 'staffId'): Promise<UserAuthView> {
//   const qb = this.userAuthViewRepository.createQueryBuilder('uav');
//   if (field === 'matriculationId') {
//     qb.where('uav.matriculationId = :identifier', { identifier });
//   } else if (field === 'staffId') {
//     qb.where('uav.staffId = :identifier', { identifier });
//   } else if (field === 'email') {
//     qb.where('uav.email = :identifier', { identifier });
//   } else {
//     // Fallback (if no field is provided, search across all identifiers)
//     qb.where('uav.email = :identifier', { identifier })
//       .orWhere('uav.matriculationId = :identifier', { identifier })
//       .orWhere('uav.staffId = :identifier', { identifier });
//   }
//   return qb.getOne();
// }

// }



import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { Student } from './entities/student.entity';
import { Lecturer } from './entities/lecturer.entity';
import { Admin } from './entities/admin.entity';
import { UserAuthView } from './entities/user.auth.view.entity';
import { Role } from './enums/roles.enum';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Student)
    private studentRepository: Repository<Student>,
    @InjectRepository(Lecturer)
    private lecturerRepository: Repository<Lecturer>,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
    @InjectRepository(UserAuthView)
    private userAuthViewRepository: Repository<UserAuthView>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Check if user exists
    const existing = await this.userRepository.findOne({ where: { email: createUserDto.email } });
    if (existing) {
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }

    // Create base user (ensure email is not verified initially)
    const user = this.userRepository.create({
      firstName: createUserDto.firstName,
      middleName: createUserDto.middleName,
      otherNames: createUserDto.otherNames,
      email: createUserDto.email,
      image: createUserDto.image,
      role: createUserDto.role,
      twoFactorEnabled: createUserDto.twoFactorEnabled ?? false,
      // New field added with default false:
      isEmailVerified: false,
    });
    const savedUser = await this.userRepository.save(user);

    // Create role-specific profile
    switch (createUserDto.role) {
      case Role.STUDENT:
        if (!createUserDto.matriculationId) {
          throw new HttpException('Matriculation ID required for students', HttpStatus.BAD_REQUEST);
        }
        const student = this.studentRepository.create({
          user: savedUser,
          matriculationId: createUserDto.matriculationId,
        });
        await this.studentRepository.save(student);
        break;
      case Role.LECTURER_FREE:
      case Role.LECTURER_BASIC:
      case Role.LECTURER_PREMIUM:
        if (!createUserDto.staffId) {
          throw new HttpException('Staff ID required for lecturers', HttpStatus.BAD_REQUEST);
        }
        const lecturer = this.lecturerRepository.create({
          user: savedUser,
          staffId: createUserDto.staffId,
        });
        await this.lecturerRepository.save(lecturer);
        break;
      case Role.ADMIN_FREE:
      case Role.ADMIN_BASIC:
      case Role.ADMIN_PREMIUM:
      case Role.SUPERADMIN:
        if (!createUserDto.staffId) {
          throw new HttpException('Staff ID required for admins', HttpStatus.BAD_REQUEST);
        }
        const admin = this.adminRepository.create({
          user: savedUser,
          staffId: createUserDto.staffId,
          adminType: createUserDto.role,
        });
        await this.adminRepository.save(admin);
        break;
      default:
        break;
    }
    return savedUser;
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    // Retrieve the base user
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    // Update common properties
    Object.assign(user, {
      firstName: updateUserDto.firstName,
      middleName: updateUserDto.middleName,
      otherNames: updateUserDto.otherNames,
      email: updateUserDto.email,
      image: updateUserDto.image,
      ...(updateUserDto.twoFactorEnabled !== undefined && { twoFactorEnabled: updateUserDto.twoFactorEnabled }),
    });
    const updatedUser = await this.userRepository.save(user);

    // Update role-specific details
    if (updatedUser.role === Role.STUDENT && updateUserDto.matriculationId) {
      const studentProfile = await this.studentRepository.findOne({ where: { user: updatedUser } });
      if (studentProfile) {
        studentProfile.matriculationId = updateUserDto.matriculationId;
        await this.studentRepository.save(studentProfile);
      }
    }
    if (
      (updatedUser.role === Role.LECTURER_FREE ||
       updatedUser.role === Role.LECTURER_BASIC ||
       updatedUser.role === Role.LECTURER_PREMIUM) &&
      updateUserDto.staffId
    ) {
      const lecturerProfile = await this.lecturerRepository.findOne({ where: { user: updatedUser } });
      if (lecturerProfile) {
        lecturerProfile.staffId = updateUserDto.staffId;
        await this.lecturerRepository.save(lecturerProfile);
      }
    }
    if (
      (updatedUser.role === Role.ADMIN_FREE ||
       updatedUser.role === Role.ADMIN_BASIC ||
       updatedUser.role === Role.ADMIN_PREMIUM ||
       updatedUser.role === Role.SUPERADMIN) &&
      updateUserDto.staffId
    ) {
      const adminProfile = await this.adminRepository.findOne({ where: { user: updatedUser } });
      if (adminProfile) {
        adminProfile.adminType = updatedUser.role;
        await this.adminRepository.save(adminProfile);
      }
    }
    return updatedUser;
  }

  async delete(id: number): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Delete associated profile depending on role
    switch (user.role) {
      case Role.STUDENT:
        await this.studentRepository.delete({ user });
        break;
      case Role.LECTURER_FREE:
      case Role.LECTURER_BASIC:
      case Role.LECTURER_PREMIUM:
        await this.lecturerRepository.delete({ user });
        break;
      case Role.ADMIN_FREE:
      case Role.ADMIN_BASIC:
      case Role.ADMIN_PREMIUM:
      case Role.SUPERADMIN:
        await this.adminRepository.delete({ user });
        break;
      default:
        break;
    }

    await this.userRepository.delete(id);
    return { message: 'User deleted successfully' };
  }

  async findById(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return user;
  }

  // Helper: Find user by email.
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  // New method: Mark a user's email as verified.
  async markEmailVerified(userId: number): Promise<void> {
    await this.userRepository.update(userId, { isEmailVerified: true });
  }

  // New method: Check if a user's email is verified.
  async isEmailVerified(userId: number): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    return user?.isEmailVerified ?? false;
  }

  // New method: Delete a user by ID (wrapper for delete)
  async deleteById(userId: number): Promise<{ message: string }> {
    return this.delete(userId);
  }

  // New method: Retrieve a user from the authentication view by identifier.
  async findByAuthIdentifier(identifier: string, field?: 'email' | 'matriculationId' | 'staffId'): Promise<UserAuthView> {
    const qb = this.userAuthViewRepository.createQueryBuilder('uav');
    if (field === 'matriculationId') {
      qb.where('uav.matriculationId = :identifier', { identifier });
    } else if (field === 'staffId') {
      qb.where('uav.staffId = :identifier', { identifier });
    } else if (field === 'email') {
      qb.where('uav.email = :identifier', { identifier });
    } else {
      qb.where('uav.email = :identifier', { identifier })
        .orWhere('uav.matriculationId = :identifier', { identifier })
        .orWhere('uav.staffId = :identifier', { identifier });
    }
    return qb.getOne();
  }
}
