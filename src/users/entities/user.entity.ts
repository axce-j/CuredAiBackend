// import { Expose } from 'class-transformer';
// import {
//   Column,
//   CreateDateColumn,
//   Entity,
//   PrimaryGeneratedColumn,
//   Unique,
// } from 'typeorm';
// import { Role } from '../enums/roles.enum';

// @Entity()
// @Unique(['email'])
// export class User {
//   @PrimaryGeneratedColumn()
//   @Expose()
//   id: number;

//   @Column('varchar')
//   @Expose()
//   firstName: string;

//   @Column('varchar')
//   @Expose()
//   middleName: string;

//   @Column('varchar')
//   @Expose()
//   otherNames: string;

//   @Column({ unique: true })
//   @Expose()
//   email: string;

//   @Column({ nullable: true })
//   @Expose()
//   image?: string;

//   @Column({
//     type: 'enum',
//     enum: Role,
//     default: Role.STUDENT,
//   })
//   @Expose()
//   role: Role;

//   // New two-factor enabled field:
//   @Column({ default: false })
//   @Expose()
//   twoFactorEnabled: boolean;

//   @CreateDateColumn()
//   @Expose()
//   createdAt: Date;
// }



import { Expose } from 'class-transformer';
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';
import { Role } from '../enums/roles.enum';

@Entity()
@Unique(['email'])
export class User {
  @PrimaryGeneratedColumn()
  @Expose()
  id: number;

  @Column('varchar')
  @Expose()
  firstName: string;

  @Column('varchar')
  @Expose()
  middleName: string;

  @Column('varchar')
  @Expose()
  otherNames: string;

  @Column({ unique: true })
  @Expose()
  email: string;

  @Column({ nullable: true })
  @Expose()
  image?: string;

  @Column({
    type: 'enum',
    enum: Role,
    default: Role.STUDENT,
  })
  @Expose()
  role: Role;

  @Column({ default: false })
  @Expose()
  twoFactorEnabled: boolean;

  // New email verification column (defaults to false)
  @Column({ default: false })
  @Expose()
  isEmailVerified: boolean;

  @CreateDateColumn()
  @Expose()
  createdAt: Date;
}
