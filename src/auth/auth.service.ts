import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from 'generated/prisma/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async login({ dto }: { dto: AuthDto }) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new BadRequestException('Credentials incorrect');
    }

    const isPasswordValid = await argon.verify(user.password, dto.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Credentials incorrect');
    }

    // Exclude password
    const { password, ...safeUser } = user;

    return {
      message: 'User logged in successfully',
      user: safeUser,
    };
  }

  async signup({ dto }: { dto: AuthDto }) {
    try {
      const hash = await argon.hash(dto.password);

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
        select: {
          email: true,
          id: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      return {
        message: 'User created successfully',
        user,
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials taken, please try another email',
          );
        }
      }
      throw error;
    }
  }
}
