import { Controller, Get, Post, Body, Patch, Param, Delete, ParseIntPipe, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { SignupUserDto } from './dto/signup-user.dto';
import { LoginUserDto } from './dto/login-user.dto';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get()
  async findAll(){
    return this.authService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string){
    return this.authService.findOne(id);
  }

  @Post('signup')
  async signup(@Body(ValidationPipe) user: SignupUserDto){
    return this.authService.signup(user);
  }

  @Post('verifyemail')
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto){
    return this.authService.verifyEmail(verifyEmailDto);
  }

  @Post('login')
  async login(@Body(ValidationPipe) user: LoginUserDto){
    return this.authService.login(user);
  }

  @Patch(':id')
  async updateUser(@Param('id') id: string, @Body(ValidationPipe) user: UpdateUserDto){
    return this.authService.updateUser(id, user);
  }

  @Delete(':id')
  async deleteOne(@Param('id') id: string){
    return this.authService.deleteOne(id);
  }
}
