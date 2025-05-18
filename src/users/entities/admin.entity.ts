import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
} from "typeorm";
import { User } from "./user.entity";
import { Role } from "../enums/roles.enum";

@Entity()
export class Admin {
  @PrimaryGeneratedColumn()
  id: number;

  @OneToOne(() => User, { cascade: true })
  @JoinColumn()
  user: User;
  // For example, if you want to store a staffId for admins:
  @Column({ unique: true, nullable: true })
  staffId?: string;

  // This column helps further specify admin type (e.g., free, basic, premium, or superadmin)
  @Column({
    type: "enum",
    enum: Role,
  })
  adminType: Role;
}
