import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

// Import all entities
import { User } from 'src/users/entities/user.entity';
import { Admin } from 'src/users/entities/admin.entity';
import { Lecturer } from 'src/users/entities/lecturer.entity';
import { Student } from 'src/users/entities/student.entity';
import { UserAuthView } from 'src/users/entities/user.auth.view.entity';
import { Auth } from 'src/authentication/auth.entity';


@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('RENDER_URL'), // Ensure this is set in the .env file
        entities: [
          User,
          Admin,
          Lecturer,
          Student,
          UserAuthView, // Added the new user authentication view
          Auth
          // Address,
          // Posts,
          // Category,
          // Challenge,
          // PolygonBasedClassPerimeter,
          // Institution,
          // Course,
          // Semester,
          // AttendanceSession,
          // AttendanceAuthentication,
        ],
        synchronize: true, // Set to false in production and use migrations
        ssl: {
          rejectUnauthorized: false, // Required for some cloud database providers
        },
      }),
    }),
  ],
})
export class DatabaseModule {}
