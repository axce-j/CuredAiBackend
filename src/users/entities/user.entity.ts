import { Expose } from 'class-transformer';
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

@Entity()
@Unique(['email'])
export class User {
  @PrimaryGeneratedColumn()
  @Expose()
  id: number;

  @Column('varchar')
  @Expose()
  fullName: string;

  

  @Column({ unique: true })
  @Expose()
  email: string;

  

  @Column({ default: false })
  @Expose()
  twoFactorEnabled: boolean;

  @Column({ default: false })
  @Expose()
  isEmailVerified: boolean;

  @CreateDateColumn()
  @Expose()
  createdAt: Date;
}
