import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signUp')
  signUp(@Body() dto: AuthDto) {
    return this.authService.signup({ dto });
  }
  @Post('login')
  login(@Body() dto: AuthDto) {
    return this.authService.login({ dto });
  }
}
