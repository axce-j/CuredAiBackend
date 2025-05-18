// import { NestFactory } from '@nestjs/core';
// import { AppModule } from './app.module';
// import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
// import * as cookieParser from 'cookie-parser';

// async function bootstrap() {
//   const app = await NestFactory.create(AppModule);

//   // Middleware for parsing cookies
//   app.use(cookieParser());

//   // Swagger configuration
//   const swaggerConfig = new DocumentBuilder()
//     .setTitle('API with NestJS')
//     .setDescription('Documentation for the Ateck app')
//     .setVersion('1.0')
//     .addBearerAuth(
//       {
//         description:
//           'Please enter the token in the following format: Bearer <JWT>',
//         name: 'Authorization',
//         bearerFormat: 'Bearer',
//         scheme: 'Bearer',
//         type: 'http',
//         in: 'Header',
//       },
//       'access-token',
//     )
//     .build();
//   const document = SwaggerModule.createDocument(app, swaggerConfig);
//   SwaggerModule.setup('api/docs', app, document);

//   // Enable CORS
//   app.enableCors({
//     origin: [
//       'http://localhost:8081',
//       'http://192.168.100.4:8081',
//       'http://192.168.43.23:3000',
//       'http://localhost:5173',
//     ], // Allow your mobile app address
//     methods: ['GET', 'POST', 'PUT', 'UPDATE','DELETE'],
//     credentials: true, // ✅ Allow cookies to be sent in requests

//   });

//   // Set global prefix for all routes
//   app.setGlobalPrefix('api');

//   // Configure port and host
//   const port = parseInt(process.env.PORT, 10) || 3000;
//   const host = process.env.HOST || '0.0.0.0'; // For Android emulator use '10.0.2.2'

//   // Start the application
//   await app.listen(port, host);
//   console.log(`Application is running on: http://${host}:${port}`);
// }

// bootstrap();



import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Middleware for parsing cookies
  app.use(cookieParser());

  // Swagger configuration
  const swaggerConfig = new DocumentBuilder()
    .setTitle('API with NestJS')
    .setDescription('Documentation for the Ateck app')
    .setVersion('1.0')
    .addBearerAuth(
      {
        description: 'Please enter the token in the following format: Bearer <JWT>',
        name: 'Authorization',
        bearerFormat: 'Bearer',
        scheme: 'Bearer',
        type: 'http',
        in: 'Header',
      },
      'access-token',
    )
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document);

  // ✅ Fix CORS to Allow Cookies
  app.enableCors({
    origin: [
      'http://localhost:8081',
      'http://192.168.100.4:8081',
      'http://192.168.43.23:3000',
      'http://localhost:5173',
      'http://localhost:3001',


    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true, // ✅ Allow sending & receiving cookies
  });

  // ✅ Ensure Cookies Are Sent Correctly
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*'); // Allow dynamic origins
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    next();
  });

  // ✅ Set Global Prefix
  app.setGlobalPrefix('api');

  // ✅ Configure Port & Host
  const port = parseInt(process.env.PORT, 10) || 3000;
  const host = process.env.HOST || '0.0.0.0'; // Keep for mobile compatibility

  // Start the application
  await app.listen(port, host);
  console.log(`Application is running on: http://${host}:${port}`);
}

bootstrap();
