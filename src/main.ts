// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.enableCors({
    origin: config.get<string>('FRONTEND_URL'), // <-- allow Angular frontend
    credentials: true,
  });
  
  app.use(cookieParser());
  await app.listen(3000);
  console.log('Server running on http://localhost:3000');
}
bootstrap();
