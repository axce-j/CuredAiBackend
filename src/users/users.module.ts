import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersController } from './controllers/users.controller';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { Student } from './entities/student.entity';
import { Lecturer } from './entities/lecturer.entity';
import { Admin } from './entities/admin.entity';
import { UserAuthView } from './entities/user.auth.view.entity';
// import { UserAuthView } from './entities/user-auth.view';

@Module({
  imports: [TypeOrmModule.forFeature([User, Student, Lecturer, Admin, UserAuthView])],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService], // ✅ Ensure this line is present
})
export class UsersModule {}
