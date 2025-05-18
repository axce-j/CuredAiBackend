import { ViewEntity, ViewColumn } from "typeorm";
import { Role } from "../enums/roles.enum";

@ViewEntity({
  expression: `
    SELECT 
      u.id as id,
      u."firstName" as "firstName",
      u."middleName" as "middleName",
      u."otherNames" as "otherNames",
      u.email as email,
      u.role as role,
      s."matriculationId" as "matriculationId",
      COALESCE(l."staffId", a."staffId") as "staffId"
    FROM "user" u
    LEFT JOIN student s ON s."userId" = u.id
    LEFT JOIN lecturer l ON l."userId" = u.id
    LEFT JOIN admin a ON a."userId" = u.id
  `,
})
export class UserAuthView {
  @ViewColumn()
  id: number;

  @ViewColumn()
  firstName: string;

  @ViewColumn()
  otherNames: string;

  @ViewColumn()
  email: string;

  @ViewColumn()
  role: Role;

  @ViewColumn()
  matriculationId?: string;

  @ViewColumn()
  staffId?: string;
}
