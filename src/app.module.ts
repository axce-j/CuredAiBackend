import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { AuthenticationModule } from './authentication/authentication.module';
// import { PostModule } from './post/post.module';
// import { CategoryModule } from './category/category.module';
import * as Joi from 'joi';
// import { ChallengeModule } from './challenges/challenge.module';
// import { PolygonBasedClassPerimeterModule } from './clasPerimeter/polygonBasedGeofencing/polygonClassPerimeter.module';
// import { Institution } from './institution/institution.entity';
// import { InstitutionModule } from './institution/institution.module';
// import { CourseModule } from './courses/courses.module';
// import { SemesterModule } from './semester/semester.module';
// import { AttendanceSessionModule } from './attendanceSessions/attendanceSessions.module';
// import { AttendanceAuthentication } from './gpsVerification/gpsVerification.entity';
// import { AttendanceAuthenticationModule } from './gpsVerification/gpsVerification.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        POSTGRES_HOST: Joi.string(),
        POSTGRES_PORT: Joi.number(),
        POSTGRES_USER: Joi.string(),
        POSTGRES_PASSWORD: Joi.string(),
        POSTGRES_DB: Joi.string(),
        PORT: Joi.number(),
        JWT_SECRET: Joi.string().required(),
        JWT_EXPIRATION_TIME: Joi.string().required(),
      }),
    }),
    DatabaseModule,
    AuthenticationModule,
    UsersModule,
    // PostModule,
    // CategoryModule,
    // ChallengeModule,
    // PolygonBasedClassPerimeterModule,
    // InstitutionModule,
    // CourseModule,
    // SemesterModule,
    // AttendanceSessionModule,
    // AttendanceAuthenticationModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
