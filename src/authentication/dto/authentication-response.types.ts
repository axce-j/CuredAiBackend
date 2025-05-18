export type TwoFactorResponse = {
    statusCode: number;
    message: string;
    requiresTwoFactor: true;
    userId: number;
    role:string;
  };
  
  export type AuthenticatedUser = {
    id: number;
    fullName: string;
    
    email: string;
    
    twoFactorEnabled: boolean;
    // Add more user fields if needed
  };
  
  export type AuthenticationResponse = TwoFactorResponse | AuthenticatedUser;
  