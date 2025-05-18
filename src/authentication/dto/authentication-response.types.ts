export type TwoFactorResponse = {
    statusCode: number;
    message: string;
    requiresTwoFactor: true;
    userId: number;
    role:string;
  };
  
  export type AuthenticatedUser = {
    id: number;
    firstName: string;
    middleName: string;
    otherNames: string;
    role: string;
    email: string;
    matriculationId?: string;
    staffId?: string;
    twoFactorEnabled: boolean;
    // Add more user fields if needed
  };
  
  export type AuthenticationResponse = TwoFactorResponse | AuthenticatedUser;
  