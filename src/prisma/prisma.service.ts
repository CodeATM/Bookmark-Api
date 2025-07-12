import { Injectable } from '@nestjs/common';
import { PrismaClient } from 'generated/prisma';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor() {
    super({
      datasources: {
        db: {
          url: "postgresql://postgres:password_123@localhost:5434/mydb?schema=public",
        },
      },
    });
  }
}
